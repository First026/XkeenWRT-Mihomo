#!/usr/bin/env python3
"""One bounded x86 OpenWrt r1 -> r2 HTTP Start scenario."""
import os
import pty
import re
import selectors
import signal
import subprocess
import sys
import time
from pathlib import Path

if len(sys.argv) != 2 or not sys.argv[1].startswith('/tmp/'):
    sys.exit('usage: upgrade-test.py /tmp/serial.log')
serial = Path(sys.argv[1])
if serial.exists():
    sys.exit('serial log already exists')
os.umask(0o077)
runner = Path(__file__).resolve().parent / 'run.sh'
master, slave = pty.openpty()
process = subprocess.Popen([str(runner), '--capture', str(serial)], stdin=slave,
                           stdout=slave, stderr=slave, close_fds=True,
                           start_new_session=True)
os.close(slave)
selector = selectors.DefaultSelector()
selector.register(master, selectors.EVENT_READ)
started = time.monotonic()
observed = []
error = None

def read_until(pattern, limit=420):
    segment = bytearray()
    deadline = min(started + 570, time.monotonic() + limit)
    while not re.search(pattern, segment.replace(b'\r', b''), re.M):
        if time.monotonic() > deadline:
            raise TimeoutError('guest deadline')
        for key, _ in selector.select(0.2):
            try:
                chunk = os.read(key.fd, 4096)
            except OSError:
                chunk = b''
            if chunk:
                segment.extend(chunk)
                if len(segment) > 262144:
                    raise RuntimeError('interactive output limit')
        if process.poll() is not None:
            raise RuntimeError('runner exited before guest prompt')
    return segment.decode('utf-8', 'replace').replace('\r', '')

def send_command(line):
    for offset in range(0, len(line), 64):
        os.write(master, line[offset:offset + 64])
        time.sleep(0.03)
    result = read_until(rb'root@[^\n]*# ')
    for item in result.splitlines():
        if item.startswith('UPGRADE_'):
            observed.append(item)
    return result

def drain_and_wait():
    deadline = time.monotonic() + 60
    while process.poll() is None:
        if time.monotonic() > deadline:
            raise TimeoutError('guest shutdown deadline')
        for key, _ in selector.select(0.2):
            try:
                os.read(key.fd, 4096)
            except OSError:
                pass
    for key, _ in selector.select(0):
        try:
            os.read(key.fd, 4096)
        except OSError:
            pass
    return process.wait()

try:
    read_until(rb'Please press Enter to activate this console\.', 90)
    os.write(master, b'\n')
    read_until(rb'root@[^\n]*# ')
    result = send_command(b'/usr/share/xkeen-lab-packages/upgrade-guest.sh\n')
    for item in result.splitlines():
        if item.startswith('UPGRADE_'):
            observed.append(item)
    if any(item.startswith('UPGRADE_FAIL=') for item in observed):
        raise RuntimeError('guest reported upgrade failure')
    expected = [
        'UPGRADE_R1_ACTIVE=manual-core-running',
        'UPGRADE_R2_STOPPED_RECEIPT=PASS',
        'UPGRADE_HTTP_START=PASS',
        'UPGRADE_HELPER_READY=PASS',
        'UPGRADE_CORE_RUNNING=PASS',
        'UPGRADE_PASS=active-manual-r1,upgrade-r2,cleanup-receipt,explicit-http-start,new-helper-ready,core-running',
    ]
    if any(item not in observed for item in expected):
        raise RuntimeError('guest result markers incomplete')
    os.write(master, b'poweroff -f\n')
    if drain_and_wait() != 0:
        raise RuntimeError('runner returned nonzero')
except (OSError, TimeoutError, RuntimeError) as exc:
    error = str(exc)
finally:
    if process.poll() is None:
        try:
            os.write(master, b'poweroff -f\n')
            drain_and_wait()
        except (OSError, TimeoutError):
            process.send_signal(signal.SIGTERM)
            try:
                process.wait(timeout=55)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
            error = (error or 'runner cleanup failed') + '; runner terminated'
    selector.close()
    os.close(master)

if error:
    sys.exit(f'FAIL: {error}; serial={serial}')
if not serial.is_file() or serial.stat().st_size > 2 * 1024 * 1024:
    sys.exit('FAIL: bounded serial log missing or oversized')
for item in expected:
    if item.startswith('UPGRADE_PASS=') or item.startswith('UPGRADE_FAIL='):
        continue
    print(item)
print(expected[-1])
print(f'UPGRADE_SERIAL={serial}')
