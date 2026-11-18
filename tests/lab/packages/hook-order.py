#!/usr/bin/env python3
"""Порядок штатных OpenWrt package hooks в одноразовой VM без NIC."""
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
    sys.exit('usage: hook-order.py')
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

commands = (
    b"mkdir -p /lib/apk/packages; printf '#!/bin/sh\\necho \"$1\" >> /tmp/xk-hook-order\\n' > /etc/init.d/xk-hook-probe; chmod 755 /etc/init.d/xk-hook-probe; echo /etc/init.d/xk-hook-probe > /lib/apk/packages/xk-hook-probe.list; : > /tmp/xk-hook-order\n",
    b". /lib/functions.sh; pkgname=xk-hook-probe; IPKG_INSTROOT=; default_prerm; echo custom-prerm >> /tmp/xk-hook-order; printf 'LAB_PRERM='; tr '\\n' ',' < /tmp/xk-hook-order; echo\n",
    b": > /tmp/xk-hook-order; default_postinst; echo custom-postinst >> /tmp/xk-hook-order; printf 'LAB_POSTINST='; tr '\\n' ',' < /tmp/xk-hook-order; echo\n",
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

expected = ['LAB_PRERM=disable,stop,custom-prerm,', 'LAB_POSTINST=enable,start,custom-postinst,']
if observed != expected:
    sys.exit(f'FAIL: unexpected hook order: {observed!r}')
print('PASS: default hooks run before package-specific hooks')
