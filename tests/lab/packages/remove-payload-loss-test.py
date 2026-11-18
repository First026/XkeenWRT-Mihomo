#!/usr/bin/env python3
"""One bounded Remove request → payload loss → persistent rescue scenario."""
import os
import pty
import re
import selectors
import signal
import subprocess
import sys
import time
from pathlib import Path

if (len(sys.argv) not in (2, 3) or not sys.argv[1].startswith('/tmp/')
        or (len(sys.argv) == 3 and sys.argv[2] != '--trace')):
    sys.exit('usage: remove-payload-loss-test.py /tmp/serial.log [--trace]')
serial = Path(sys.argv[1])
trace_mode = len(sys.argv) == 3
if serial.exists():
    sys.exit('serial log already exists')
runner_log = Path(str(serial) + '.runner.log')
if runner_log.exists():
    sys.exit('runner log already exists')
os.umask(0o077)
runner_output = runner_log.open('xb')
runner_output_size = 0

def record_runner_output(chunk):
    global runner_output_size
    if runner_output_size + len(chunk) > 2 * 1024 * 1024:
        raise RuntimeError('runner output limit')
    runner_output.write(chunk)
    runner_output.flush()
    runner_output_size += len(chunk)

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
                record_runner_output(chunk)
                segment.extend(chunk)
                if len(segment) > 262144:
                    raise RuntimeError('interactive output limit')
        if process.poll() is not None:
            raise RuntimeError('runner exited before guest prompt')
    result = segment.decode('utf-8', 'replace').replace('\r', '')
    observed.extend(line for line in result.splitlines() if line.startswith('REMOVE_PENDING_'))
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
                    record_runner_output(chunk)
            except OSError:
                pass
    for key, _ in selector.select(0):
        try:
            chunk = os.read(key.fd, 4096)
            if chunk:
                record_runner_output(chunk)
        except OSError:
            pass
    return process.wait()

try:
    read_until(rb'Please press Enter to activate this console\.', 90)
    os.write(master, b'\n')
    read_until(rb'root@[^\n]*# ')
    command = (b'sh -x /usr/share/xkeen-lab-packages/remove-payload-loss-guest.sh\n'
               if trace_mode else b'/usr/share/xkeen-lab-packages/remove-payload-loss-guest.sh\n')
    for offset in range(0, len(command), 64):
        os.write(master, command[offset:offset + 64])
        time.sleep(0.03)
    read_until(rb'root@[^\n]*# ')
    failure_markers = [item for item in observed if item.startswith('REMOVE_PENDING_FAIL=')]
    if trace_mode and failure_markers:
        os.write(master, b"logread -e 'recovery stopped' | tail -n 8\n")
        read_until(rb'root@[^\n]*# ')
    elif not trace_mode and failure_markers:
        raise RuntimeError('guest reported Remove payload-loss failure')
    expected = [
        'REMOVE_PENDING_BASELINE=active-r2,real-history-json',
        'REMOVE_PENDING_HELPER_IDENTITY=PASS',
        'REMOVE_PENDING_LOCKS=RECOVERY_HELD_MUTATION_FREE',
        'REMOVE_PENDING_APK_SCRIPTS_OPTION=verified-by-help-content',
        'REMOVE_PENDING_HELPER_STOPPED=PASS',
        'REMOVE_PENDING_REQUESTED=PASS',
        'REMOVE_PENDING_WAITER_INTERRUPTED=PASS',
        'REMOVE_PENDING_REQUEST_ID_STABLE=PASS',
        'REMOVE_PENDING_PAYLOAD_ABSENT=PASS',
        'REMOVE_PENDING_RECEIPT_UNCHANGED=PASS',
        'REMOVE_PENDING_CORE_ACTIVE_BEFORE_RESUME=PASS',
        'REMOVE_PENDING_DATA_PRESERVED=PASS',
        'REMOVE_PENDING_CLEANUP_COMPLETE=PASS',
        'REMOVE_PENDING_SAME_HELPER=PASS',
        'REMOVE_PENDING_FINAL_DATA_PRESERVED=PASS',
        'REMOVE_PENDING_PASS=durable-request,payload-absent,resume-same-rescue,cleanup-complete',
    ]
    if trace_mode:
        if not failure_markers and any(item not in observed for item in expected):
            raise RuntimeError('trace run neither reached target failure nor full pass')
    elif any(item not in observed for item in expected):
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
    runner_output.close()

if error:
    sys.exit(f'FAIL: {error}; serial={serial}; runner_log={runner_log}')
if not serial.is_file() or serial.stat().st_size > 2 * 1024 * 1024:
    sys.exit('FAIL: bounded serial log missing or oversized')
if runner_log.stat().st_size > 2 * 1024 * 1024:
    sys.exit('FAIL: bounded runner log oversized')
if trace_mode:
    print(f'REMOVE_PENDING_TRACE_CAPTURE=PASS,failure-present={bool(failure_markers)}')
else:
    for item in expected:
        print(item)
print(f'REMOVE_PENDING_SERIAL={serial}')
print(f'REMOVE_PENDING_RUNNER_LOG={runner_log}')
