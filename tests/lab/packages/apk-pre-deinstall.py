#!/usr/bin/env python3
"""Порядок штатных OpenWrt package hooks в одноразовой VM без NIC."""
import os
import hashlib
import tempfile
import pty
import re
import selectors
import signal
import subprocess
import sys
import time
from pathlib import Path

if sys.argv[1:]:
    sys.exit('usage: apk-pre-deinstall.py')
arm = False
runner = Path(__file__).resolve().parents[1] / 'openwrt-vm' / 'run.sh'
master, slave = pty.openpty()
p = subprocess.Popen([str(runner)] + (['--arm64-baseline'] if arm else []),
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

with tempfile.TemporaryDirectory(prefix='xkeen-apk-probe-') as temp:
    root = Path(temp)
    owned = root / 'files/usr/share/xk-apk-probe/owned'
    owned.parent.mkdir(parents=True)
    owned.write_text('owned\n')
    hook = root / 'pre-deinstall'
    hook.write_text('#!/bin/sh\necho hook-ran > /tmp/xk-apk-hook; exit 1\n')
    hook.chmod(0o755)
    package = root / 'probe.apk'
    apk = os.environ.get('XK_APK_MKPKG', '/tmp/xkeen-apk-host/bin/apk')
    subprocess.run([apk, 'mkpkg', '--info', 'name:xk-apk-probe', '--info',
                    'version:1-r1', '--info', 'arch:x86_64', '--info', 'license:MIT',
                    '--script', f'pre-deinstall:{hook}', '--files', str(root / 'files'),
                    '--output', str(package)], check=True)
    fixture = package.read_bytes()
print('FIXTURE_SHA256=' + hashlib.sha256(fixture).hexdigest())
commands = (b": > /tmp/xk-apk-probe.apk\n",) + tuple(
    b"printf '" + b''.join(("\\%03o" % byte).encode() for byte in fixture[i:i + 24]) + b"' >> /tmp/xk-apk-probe.apk\n"
    for i in range(0, len(fixture), 24)
) + (
    b"printf 'LAB_FILE='; wc -c < /tmp/xk-apk-probe.apk\n",
    b"apk add --no-network --allow-untrusted --force-non-repository /tmp/xk-apk-probe.apk >/tmp/xk-apk-add.log 2>&1; printf 'LAB_ADD=%s|' \"$?\"; test -f /usr/share/xk-apk-probe/owned && echo present || echo absent; printf 'LAB_ADD_LOG='; tr '\\n' '|' </tmp/xk-apk-add.log; echo\n",
    b"apk del --no-network xk-apk-probe >/tmp/xk-apk-del.log 2>&1; printf 'LAB_DEL=%s|' \"$?\"; test -f /usr/share/xk-apk-probe/owned && printf present || printf absent; printf '|'; test -f /tmp/xk-apk-hook && echo hook-ran || echo no-hook; cat /tmp/xk-apk-del.log\n",
)
observed = []
error = None
try:
    read_until(rb'Please press Enter to activate this console\.', 90)
    os.write(master, b'\n')
    read_until(rb'root@[^\n]*# ')
    for line in commands:
        result = command(line)
        for item in result.splitlines():
            if item.startswith('LAB_'):
                print(item)
                observed.append(item)
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

if 'LAB_ADD=0|present' not in observed or 'LAB_DEL=0|absent|hook-ran' not in observed:
    sys.exit('FAIL: synthetic package hook behavior changed: ' + repr(observed))
print('PASS: failed pre-deinstall did not prevent removal')
