#!/usr/bin/env python3
"""One bounded active Remove -> inert Reinstall -> explicit Resume scenario in an x86 VM."""
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
    sys.exit('usage: active-remove-test.py /tmp/serial.log')
serial = Path(sys.argv[1])
runner_log = Path(str(serial) + '.runner.log')
if serial.exists():
    sys.exit('serial log already exists')
if runner_log.exists():
    sys.exit('runner transcript already exists')
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
runner_output = bytearray()
runner_output_truncated = False
runner_output_limit = 1024 * 1024

def save_runner_output(chunk):
    global runner_output_truncated
    remaining = runner_output_limit - len(runner_output)
    if remaining > 0:
        runner_output.extend(chunk[:remaining])
    if len(chunk) > remaining:
        runner_output_truncated = True

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
                save_runner_output(chunk)
                segment.extend(chunk)
                if len(segment) > 262144:
                    raise RuntimeError('interactive output limit')
        if process.poll() is not None:
            raise RuntimeError('runner exited before guest prompt')
    result = segment.decode('utf-8', 'replace').replace('\r', '')
    observed.extend(line for line in result.splitlines() if line.startswith('ACTIVE_REMOVE_'))
    return result

def drain_and_wait():
    deadline = time.monotonic() + 60
    while process.poll() is None:
        if time.monotonic() > deadline:
            raise TimeoutError('guest shutdown deadline')
        for key, _ in selector.select(0.2):
            try:
                chunk = os.read(key.fd, 4096)
                if chunk:
                    save_runner_output(chunk)
            except OSError:
                pass
    for key, _ in selector.select(0):
        try:
            chunk = os.read(key.fd, 4096)
            if chunk:
                save_runner_output(chunk)
        except OSError:
            pass
    return process.wait()

try:
    read_until(rb'Please press Enter to activate this console\.', 90)
    os.write(master, b'\n')
    read_until(rb'root@[^\n]*# ')
    command = b'/usr/share/xkeen-lab-packages/active-remove-guest.sh\n'
    for offset in range(0, len(command), 64):
        os.write(master, command[offset:offset + 64])
        time.sleep(0.03)
    result = read_until(rb'root@[^\n]*# ')
    if any(item.startswith('ACTIVE_REMOVE_FAIL=') for item in observed):
        raise RuntimeError('guest reported active Remove failure')
    expected = [
        'ACTIVE_REMOVE_BASELINE=active-r3',
        'ACTIVE_REMOVE_REMOVED=stopped,rescue,remove-receipt,payload-absent,data-preserved',
        'ACTIVE_REMOVE_REINSTALL=inert-r3,remove-fence-retained,data-preserved',
        'ACTIVE_REMOVE_CONTROL=authenticated,runtime-ui-only,exact-request-id,core-stopped',
        'ACTIVE_REMOVE_START_REFUSED=remove-fence-retained,core-stopped',
        'ACTIVE_REMOVE_WRONG_REQUEST=conflict,receipt-unchanged,core-stopped',
        'ACTIVE_REMOVE_RESUME=exact-request-consumed,core-stopped,data-preserved',
        'ACTIVE_REMOVE_REPLAY_REQUEST=conflict,core-stopped,data-preserved',
        'ACTIVE_REMOVE_START=explicit-after-resume,core-running,data-preserved',
        'ACTIVE_REMOVE_PASS=active-r3,remove,inert-reinstall,ordinary-start-refused,explicit-resume-stopped,start-running,data-preserved',
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
    transcript = bytes(runner_output)
    if runner_output_truncated:
        transcript += b'\nACTIVE_REMOVE_RUNNER_TRANSCRIPT=truncated-at-1MiB\n'
    runner_log.write_bytes(transcript)
    selector.close()
    os.close(master)

if error:
    sys.exit(f'FAIL: {error}; serial={serial}')
if not serial.is_file() or serial.stat().st_size > 2 * 1024 * 1024:
    sys.exit('FAIL: bounded serial log missing or oversized')
for item in expected:
    print(item)
print(f'ACTIVE_REMOVE_SERIAL={serial}')
