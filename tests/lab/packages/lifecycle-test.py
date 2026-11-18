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
    sys.exit('usage: lifecycle-test.py')
arm = False
runner = Path(__file__).resolve().parent / 'run.sh'
master, slave = pty.openpty()
p = subprocess.Popen([str(runner)] + (['--arm64-baseline'] if arm else []),
                     stdin=slave, stdout=slave, stderr=slave, close_fds=True,
                     start_new_session=True)
os.close(slave)
sel = selectors.DefaultSelector()
sel.register(master, selectors.EVENT_READ)
start = time.monotonic()
output = bytearray()

def read_until(pattern, limit=420):
    segment = bytearray()
    deadline = min(start + 570, time.monotonic() + limit)
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

commands = (b"/usr/share/xkeen-lab-packages/lifecycle-guest.sh\n",)
observed = []
error = None
try:
    read_until(rb'Please press Enter to activate this console\.', 90)
    os.write(master, b'\n')
    read_until(rb'root@[^\n]*# ')
    for line in commands:
        result = command(line)
        for item in result.splitlines():
            if item.startswith('LIFECYCLE_'):
                print(item)
                observed.append(item)
            if item == 'LAB_VETH=cleanup-failed':
                raise RuntimeError('не удалось удалить синтетический veth')
    if any(item.startswith('LIFECYCLE_FAIL:') for item in observed):
        for diagnostic in (
            b"printf 'DIAG_PACKAGES='; apk info -v 2>/dev/null | grep '^xkeenwrt-'; echo\n",
            b"printf 'DIAG_IDENT='; . /etc/openwrt_release; echo $DISTRIB_ID; /usr/bin/xkeenwrt-ui package-version\n",
            b"printf 'DIAG_MANIFEST='; cat /usr/share/xkeenwrt/ui-manifest.json; cmp /usr/share/xkeenwrt/ui-manifest.json /usr/share/xkeenwrt/core-manifest.json; echo\n",
            b"ls -ldn /usr/bin/xkeenwrt-ui /usr/libexec/xkeenwrt/* /usr/libexec/xkeenwrt/init/* /usr/share/xkeenwrt/* /etc/init.d/xkeenwrt-*\n",
            b"busybox stat --help >/tmp/stat-test 2>&1; printf 'DIAG_BUSYBOX_STAT=%s ' $?; head -n 1 /tmp/stat-test\n",
            b"/usr/bin/apk info -v >/tmp/apk-absolute 2>&1; printf 'DIAG_ABS_APK=%s\n' $?; grep '^xkeenwrt-' /tmp/apk-absolute\n",
            b"printf 'DIAG_START='; date +%s; /usr/bin/xkeenwrt-ui package-check; printf 'DIAG_FINISH='; date +%s\n",
            b"for f in /etc/init.d/xkeenwrt-*; do printf 'DIAG_LINK=%s:' $f; readlink $f; done\n",
            b"sha256sum /usr/bin/xkeenwrt-ui /usr/libexec/xkeenwrt/mihomo /usr/libexec/xkeenwrt/xkeenwrt-validate /usr/libexec/xkeenwrt/xkeenwrt-recovery /usr/libexec/xkeenwrt/init/*\n",
        ):
            print(command(diagnostic))
    os.write(master, b'poweroff -f\n')
    try:
        p.wait(timeout=20)
    except subprocess.TimeoutExpired:
        raise RuntimeError('poweroff не завершился')
    if p.returncode:
        raise RuntimeError(f'ошибка runner: {p.returncode}')
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

expected = ['LIFECYCLE_TAMPER_GUARD=PASS', 'LIFECYCLE_INSTALL=PASS', 'LIFECYCLE_UPGRADE=PASS', 'LIFECYCLE_REMOVE=PASS', 'LIFECYCLE_REINSTALL=PASS', 'LIFECYCLE_ENOSPC_ERROR=confirmed', 'LIFECYCLE_ENOSPC_DATA=preserved', 'LIFECYCLE_ENOSPC_GUARD=PASS', 'LIFECYCLE_DONE=PASS']
if any(item not in observed for item in expected):
    print(output.decode('utf-8', 'replace')[-12000:])
    sys.exit(f'FAIL: {observed!r}')
print('PASS: inert lifecycle; review the ENOSPC version report separately')
