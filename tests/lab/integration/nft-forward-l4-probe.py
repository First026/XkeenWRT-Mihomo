#!/usr/bin/env python3
"""Фиксированная проверка наличия средств топологии в одноразовой VM."""
import os
import pty
import re
import selectors
import signal
import subprocess
import sys
import time
from pathlib import Path

if sys.argv[1:]:
    sys.exit('usage: nft-forward-l4-probe.py')
arm = False
runner = Path(__file__).resolve().parents[1] / 'openwrt-vm' / 'run.sh'
master, slave = pty.openpty()
p = subprocess.Popen([str(runner), '--isolation'],
                     stdin=slave, stdout=slave, stderr=slave, close_fds=True,
                     start_new_session=True)
os.close(slave)
sel = selectors.DefaultSelector()
sel.register(master, selectors.EVENT_READ)
start = time.monotonic()
output = bytearray()

def read_until(pattern, limit=45):
    segment = bytearray()
    deadline = min(start + 165, time.monotonic() + limit)
    while not re.search(pattern, segment.replace(b'\r', b''), re.M):
        if time.monotonic() > deadline:
            raise TimeoutError('истёк срок ожидания гостя')
        for key, _ in sel.select(0.2):
            try:
                chunk = os.read(key.fd, 4096)
            except OSError:
                chunk = b''
            output.extend(chunk)
            segment.extend(chunk)
            if len(output) > 262144:
                raise RuntimeError('превышен лимит последовательного вывода')
        if p.poll() is not None:
            raise RuntimeError('гость завершился до окончания проверки')
    return segment.decode('utf-8', 'replace').replace('\r', '')

def command(line):
    for pos in range(0, len(line), 64):
        os.write(master, line[pos:pos + 64])
        time.sleep(0.05)
    return read_until(rb'root@[^\n]*# ')

commands = (
    b"printf 'LAB_MARKER='; cat /etc/xkeenwrt-isolation-lab\n",
    b"printf 'LAB_CMDLINE='; tr ' ' '\\n' < /proc/cmdline | grep -Fxq xkeenwrt.isolation_lab=1 && echo yes || echo no\n",
    b"printf 'LAB_ABSENT='; nft list table inet xkeenwrt_digest_probe >/dev/null 2>&1 && echo no || echo yes\n",
    b"nft -j list ruleset > /tmp/xkeenwrt-nft-before.json; printf 'LAB_BASELINE=%s\\n' \"$?\"\n",
    b"printf '%s\\n' 'table inet xkeenwrt_digest_probe {' ' comment \"xkeenwrt:synthetic\"' ' chain forward {' > /tmp/xkeenwrt-nft-probe.nft\n",
    b"printf '%s\\n' '  type filter hook forward priority -1; policy accept;' '  meta l4proto ipv6-icmp icmpv6 type { 1, 2, 3, 4, 133, 134, 135, 136, 137 } return' >> /tmp/xkeenwrt-nft-probe.nft\n",
    b"printf '%s\\n' '  ether saddr aa:bb:cc:dd:ee:02 meta nfproto ipv6 drop' ' }' '}' >> /tmp/xkeenwrt-nft-probe.nft\n",
    b"nft -j -c -e -f /tmp/xkeenwrt-nft-probe.nft > /tmp/xkeenwrt-nft-check.json 2>/dev/null; printf 'LAB_CHECK_STATUS=%s\\n' \"$?\"\n",
    b"printf 'LAB_CHECK_JSON='; tr -d '\\n' < /tmp/xkeenwrt-nft-check.json; echo\n",
    b"nft -f /tmp/xkeenwrt-nft-probe.nft >/dev/null 2>&1; printf 'LAB_APPLY_STATUS=%s\\n' \"$?\"\n",
    b"printf 'LAB_APPLIED_JSON='; nft -j list table inet xkeenwrt_digest_probe | tr -d '\\n'; echo\n",
    b"nft delete table inet xkeenwrt_digest_probe >/dev/null 2>&1; printf 'LAB_DELETE_STATUS=%s\\n' \"$?\"\n",
    b"nft -j list ruleset > /tmp/xkeenwrt-nft-after.json; printf 'LAB_FOREIGN_SAME='; cmp -s /tmp/xkeenwrt-nft-before.json /tmp/xkeenwrt-nft-after.json && echo yes || echo no\n",
)
error = None
try:
    read_until(rb'Please press Enter to activate this console\.', 90)
    os.write(master, b'\n')
    read_until(rb'root@[^\n]*# ')
    expected = ('LAB_MARKER=xkeenwrt-validator-lab-v1', 'LAB_CMDLINE=yes', 'LAB_ABSENT=yes', 'LAB_BASELINE=0',
                'LAB_CHECK_STATUS=0', 'LAB_APPLY_STATUS=0', 'LAB_DELETE_STATUS=0', 'LAB_FOREIGN_SAME=yes')
    observed = []
    for line in commands:
        result = command(line)
        for item in result.splitlines():
            if item.startswith('LAB_'):
                observed.append(item)
                print(item, flush=True)
        # Проверка идентичности и отсутствия объекта precedes every mutation.
        for marker, expected_value in ((b'LAB_MARKER=', 'LAB_MARKER=xkeenwrt-validator-lab-v1'),
                                       (b'LAB_CMDLINE=', 'LAB_CMDLINE=yes'),
                                       (b'LAB_ABSENT=', 'LAB_ABSENT=yes'),
                                       (b'LAB_BASELINE=', 'LAB_BASELINE=0'),
                                       (b'LAB_CHECK_STATUS=', 'LAB_CHECK_STATUS=0'),
                                       (b'LAB_APPLY_STATUS=', 'LAB_APPLY_STATUS=0')):
            if marker in line and expected_value not in observed:
                raise RuntimeError('проверка перед действием не пройдена: ' + expected_value)
    for item in expected:
        if item not in observed:
            raise RuntimeError('отсутствует ожидаемый результат: ' + item)
    os.write(master, b'poweroff -f\n')
    try:
        p.wait(timeout=20)
    except subprocess.TimeoutExpired:
        raise RuntimeError('poweroff не завершился')
    if p.returncode:
        raise RuntimeError(f'ошибка runner: {p.returncode}')
    print('PASS: синтетическая таблица удалена, чужой ruleset неизменен')
except (OSError, TimeoutError, RuntimeError) as exc:
    error = str(exc)
finally:
    if p.poll() is None:
        p.send_signal(signal.SIGTERM)
        try:
            p.wait(timeout=55)
        except subprocess.TimeoutExpired:
            os.killpg(p.pid, signal.SIGKILL)
            p.wait()
            error = (error or 'runner не завершился') + '; очистка не подтверждена'
    sel.close()
    os.close(master)
if error:
    sys.exit('FAIL: ' + error)
