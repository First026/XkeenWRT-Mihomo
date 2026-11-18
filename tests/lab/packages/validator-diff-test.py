#!/usr/bin/env python3
"""One bounded VM run; serial-capture persists the stream before VM cleanup."""
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
    sys.exit('usage: validator-diff-test.py /tmp/NEW-SERIAL-LOG')
log = Path(sys.argv[1])
if log.exists():
    sys.exit('serial log must not exist')
runner = Path(__file__).resolve().with_name('run-validator-diff.sh')
master, slave = pty.openpty()
env = os.environ.copy()
env['XK_SERIAL_LOG'] = str(log)
p = subprocess.Popen([str(runner)], stdin=slave, stdout=slave, stderr=slave,
                     close_fds=True, start_new_session=True, env=env)
os.close(slave)
sel = selectors.DefaultSelector()
sel.register(master, selectors.EVENT_READ)
output = bytearray()
start = time.monotonic()

def until(pattern, limit):
    segment = bytearray()
    deadline = min(start + 550, time.monotonic() + limit)
    while not re.search(pattern, segment.replace(b'\r', b''), re.M):
        if time.monotonic() > deadline:
            raise TimeoutError('guest deadline')
        for key, _ in sel.select(0.2):
            try:
                chunk = os.read(key.fd, 4096)
            except OSError:
                chunk = b''
            output.extend(chunk)
            segment.extend(chunk)
            if len(output) > 2 * 1024 * 1024:
                raise RuntimeError('serial limit')
        if p.poll() is not None:
            raise RuntimeError('runner exited before marker')
    return segment.decode('utf-8', 'replace').replace('\r', '')

error = None
try:
    until(rb'Please press Enter to activate this console\.', 90)
    os.write(master, b'\n')
    until(rb'root@[^\n]*# ', 30)
    os.write(master, b'/usr/share/xkeen-lab-diagnostic/run.sh\n')
    result = until(rb'root@[^\n]*# ', 420)
    for line in result.splitlines():
        if re.fullmatch(r'DIAG_[A-Z0-9_]+=[A-Z0-9_,=-]+', line):
            print(line, flush=True)
    if 'DIAG_DONE=YES' not in result:
        raise RuntimeError('diagnostic did not complete')
    os.write(master, b'poweroff -f\n')
    p.wait(timeout=30)
    if p.returncode:
        raise RuntimeError(f'runner exit {p.returncode}')
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
            error = (error or 'runner did not finish') + '; cleanup unconfirmed'
    sel.close()
    os.close(master)
if not log.exists():
    sys.exit('FAIL: serial log missing')
print(f'SERIAL_LOG={log} BYTES={log.stat().st_size}', flush=True)
if error:
    sys.exit('FAIL: ' + error)
