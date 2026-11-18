#!/usr/bin/env python3
"""Фиксированные тесты протокола валидатора в одноразовой VM."""
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
    sys.exit('usage: awg-test.py')
runner = Path(__file__).resolve().with_name('run-awg.sh')
master, slave = pty.openpty()
p = subprocess.Popen([str(runner)],
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

identity = (b"printf 'LAB_IDENT=%s|%s|%s\\n' \"$(uname -m)\" \"$(uname -r)\" \"$(. /etc/openwrt_release; echo $DISTRIB_REVISION)\"\n"
            b"printf 'LAB_PID1=%s\\n' \"$(cat /proc/1/comm)\"\n"
            b"printf 'LAB_NET='; for i in /sys/class/net/*; do printf '%s ' \"${i##*/}\"; done; echo\n"
            b"printf 'LAB_UBUS='; ubus call system board >/dev/null && echo ok || echo failed\n"
            b"printf 'LAB_MARKER='; cat /etc/xkeenwrt-isolation-lab\n"
            b"printf 'test-sentinel-v1\\n' > /tmp/xkeenwrt-test-sentinel\n")
commands = identity.splitlines(keepends=True)
error = None
try:
    read_until(rb'Please press Enter to activate this console\.', 90)
    os.write(master, b'\n')
    read_until(rb'root@[^\n]*# ')
    for line in commands:
        result = command(line)
        if b"LAB_IDENT=" in line and not re.search(r'^LAB_IDENT=x86_64\|6\.12\.112\|r33311-981c978eff$', result, re.M):
            raise RuntimeError('неверная идентификация гостя')
        for label, expected in (('LAB_PID1', 'procd'), ('LAB_NET', 'lo '), ('LAB_UBUS', 'ok'), ('LAB_MARKER', 'xkeenwrt-validator-lab-v1')):
            if (label + '=').encode() in line and not re.search('^' + label + '=' + re.escape(expected) + '$', result, re.M):
                raise RuntimeError('неверный признак гостя: ' + label)
    result = command(b"/usr/libexec/xkeenwrt-integration/awg-smoke.sh; printf 'LAB_SCRIPT_STATUS=%s\\n' \"$?\"\n")
    if not re.search(r'^LAB_AWG_PASS=handshake,data,cleanup$', result, re.M) or not re.search(r'^LAB_SCRIPT_STATUS=0$', result, re.M):
        failure = re.search(r'^LAB_AWG_FAIL=([a-z]+)$', result, re.M)
        for code in re.findall(r'^LAB_AWG_CLIENT_STATUS=(DIAL|GREETING|CONNECT|ADDRESS|WRITE|ECHO|ACK)$', result, re.M):
            print('LAB_AWG_CLIENT_STATUS=' + code, file=sys.stderr)
        raise RuntimeError('AWG smoke не прошёл на этапе ' + (failure.group(1) if failure else 'неизвестно'))
    version = re.search(r'^LAB_CORE_VERSION=(v?1\.19\.34)$', result, re.M)
    if not version:
        raise RuntimeError('версия core не подтверждена')
    print('LAB_CORE_VERSION=' + version.group(1), flush=True)
    os.write(master, b'poweroff -f\n')
    try:
        p.wait(timeout=20)
    except subprocess.TimeoutExpired:
        raise RuntimeError('poweroff не завершился')
    if p.returncode:
        raise RuntimeError(f'ошибка runner: {p.returncode}')
    print('PASS: AWG handshake и передача данных в VM')
except (OSError, TimeoutError, RuntimeError) as exc:
    error = str(exc)
    for code in re.findall(rb'^LAB_AWG_CLIENT_STATUS=(DIAL|GREETING|CONNECT|ADDRESS|WRITE|ECHO|ACK)$', output.replace(b'\r', b''), re.M):
        print('LAB_AWG_CLIENT_STATUS=' + code.decode(), file=sys.stderr)
    for step in re.findall(rb'^LAB_AWG_STEP=(config|peerready|coreready|clientdone|handshake)$', output.replace(b'\r', b''), re.M):
        print('LAB_AWG_STEP=' + step.decode(), file=sys.stderr)
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
