#!/usr/bin/env python3
"""One bounded Remove → payload loss → real reboot → S09 recovery VM gate."""
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
    sys.exit('usage: remove-reboot-test.py /tmp/serial.log')
serial = Path(sys.argv[1])
if serial.exists():
    sys.exit('serial log already exists')
serial.parent.mkdir(parents=True, exist_ok=True)
runner_log = Path(str(serial) + '.runner.log')
if runner_log.exists():
    sys.exit('runner log already exists')

os.umask(0o077)
runner_output = runner_log.open('xb')
runner_output_size = 0
runner = Path(__file__).resolve().parent / 'run.sh'
master, slave = pty.openpty()
process = subprocess.Popen([str(runner), '--capture', str(serial), '--remove-reboot'],
                           stdin=slave, stdout=slave, stderr=slave,
                           close_fds=True, start_new_session=True)
os.close(slave)
selector = selectors.DefaultSelector()
selector.register(master, selectors.EVENT_READ)
started = time.monotonic()
stream = bytearray()
error = None

def record(chunk):
    global runner_output_size
    if runner_output_size + len(chunk) > 2 * 1024 * 1024:
        raise RuntimeError('runner output limit')
    runner_output.write(chunk)
    runner_output.flush()
    runner_output_size += len(chunk)
    stream.extend(chunk)
    if len(stream) > 2 * 1024 * 1024:
        raise RuntimeError('serial output limit')

def read_more(limit):
    if time.monotonic() > min(started + 540, time.monotonic() + limit):
        raise TimeoutError('guest deadline')
    for key, _ in selector.select(0.2):
        try:
            chunk = os.read(key.fd, 4096)
        except OSError:
            chunk = b''
        if chunk:
            record(chunk)
    if process.poll() is not None:
        raise RuntimeError('runner exited before expected guest marker')

def check_guest_failures():
    text = stream.decode('utf-8', 'replace').replace('\r', '')
    failure = re.search(r'^(?:REMOVE_PENDING_FAIL=.*|REMOVE_REBOOT_AFTER_FAIL=.*|REMOVE_REBOOT_ETC_MOUNT=FAIL-[^\n]*)$', text, re.M)
    if failure:
        raise RuntimeError('guest failure marker: ' + failure.group(0))

def wait_text(pattern, limit=240, start_offset=0):
    compiled = re.compile(pattern, re.M)
    deadline = min(started + 540, time.monotonic() + limit)
    while not compiled.search(stream[start_offset:].replace(b'\r', b'')):
        check_guest_failures()
        if time.monotonic() > deadline:
            raise TimeoutError('deadline waiting for ' + pattern.decode('ascii', 'replace'))
        read_more(limit)
    check_guest_failures()
    return stream.decode('utf-8', 'replace').replace('\r', '')

def wait_count(pattern, count, limit=120):
    compiled = re.compile(pattern, re.M)
    deadline = min(started + 540, time.monotonic() + limit)
    while len(compiled.findall(stream.replace(b'\r', b''))) < count:
        check_guest_failures()
        if time.monotonic() > deadline:
            raise TimeoutError('deadline waiting for marker count ' + str(count))
        read_more(limit)
    check_guest_failures()
    return stream.decode('utf-8', 'replace').replace('\r', '')

def send(command):
    if len(command) > 160:
        raise RuntimeError('guest command exceeds fixed short-command bound')
    for offset in range(0, len(command), 64):
        os.write(master, command[offset:offset + 64])
        time.sleep(0.03)

def marker_values(text, name):
    return re.findall(r'^' + re.escape(name) + r'=(.*)$', text, re.M)

def exactly_one(text, name):
    values = marker_values(text, name)
    if len(values) != 1 or not values[0]:
        raise RuntimeError('missing or duplicate marker ' + name)
    return values[0]

def latest(text, name):
    values = marker_values(text, name)
    if not values:
        raise RuntimeError('missing marker ' + name)
    return values[-1]

def drain_and_wait(limit=60):
    deadline = time.monotonic() + limit
    while process.poll() is None:
        if time.monotonic() > deadline:
            raise TimeoutError('guest poweroff deadline')
        for key, _ in selector.select(0.2):
            try:
                chunk = os.read(key.fd, 4096)
            except OSError:
                chunk = b''
            if chunk:
                record(chunk)
    return process.wait()

try:
    wait_text(rb'Please press Enter to activate this console\.', 90)
    wait_count(rb'^REMOVE_REBOOT_S08_SUPERVISOR=', 1, 90)
    if 'REMOVE_REBOOT_ETC_MOUNT=seeded' not in stream.decode('utf-8', 'replace'):
        raise RuntimeError('first boot did not seed persistent /etc')
    first_console_end = len(stream)
    send(b'\n')
    wait_text(rb'root@[^\n]*# ', 60, start_offset=first_console_end)
    send(b'/usr/share/xkeen-lab-packages/remove-payload-loss-guest.sh --reboot\n')
    text = wait_text(rb'^REMOVE_PENDING_REBOOT_TRIGGER=SYSRQ_B$', 300)
    if re.search(r'^REMOVE_PENDING_FAIL=', text, re.M):
        raise RuntimeError('pre-reboot guest reported failure')
    text = wait_count(rb'Please press Enter to activate this console\.', 2, 120)
    text = wait_count(rb'^REMOVE_REBOOT_S08_SUPERVISOR=', 2, 90)

    if marker_values(text, 'REMOVE_REBOOT_ETC_MOUNT') != ['seeded', 'existing']:
        raise RuntimeError('persistent /etc mount sequence was not seeded→existing')
    if marker_values(text, 'REMOVE_REBOOT_S08_STATE') != ['absent', 'requested']:
        raise RuntimeError('S08 did not observe absent then Requested')
    if marker_values(text, 'REMOVE_REBOOT_S08_SUPERVISOR') != ['absent', 'absent']:
        raise RuntimeError('S08 snapshot did not precede S09 supervisor')

    preboot_id = exactly_one(text, 'REMOVE_PENDING_REBOOT_BASELINE_BOOT_ID')
    expected_owner = exactly_one(text, 'REMOVE_PENDING_REBOOT_BASELINE_OWNER_ID')
    expected_request = exactly_one(text, 'REMOVE_PENDING_REBOOT_BASELINE_REQUEST_ID')
    expected_receipt = exactly_one(text, 'REMOVE_PENDING_REBOOT_BASELINE_RECEIPT_SHA256')
    exactly_one(text, 'REMOVE_PENDING_REBOOT_BASELINE_HELPER_EXE_SHA256')
    s08_boot_ids = marker_values(text, 'REMOVE_REBOOT_S08_BOOT_ID')
    s08_receipts = marker_values(text, 'REMOVE_REBOOT_S08_RECEIPT_SHA256')
    s08_kinds = marker_values(text, 'REMOVE_REBOOT_S08_KIND')
    s08_owners = marker_values(text, 'REMOVE_REBOOT_S08_OWNER')
    s08_requests = marker_values(text, 'REMOVE_REBOOT_S08_REQUEST_ID')
    if len(s08_boot_ids) != 2 or s08_boot_ids[0] != preboot_id or s08_boot_ids[1] == preboot_id:
        raise RuntimeError('second S08 boot-id did not change')
    if s08_receipts != ['absent', expected_receipt] or s08_kinds != ['absent', 'remove']:
        raise RuntimeError('S08 receipt hash/kind did not preserve Requested')
    if s08_owners != ['absent', expected_owner] or s08_requests != ['absent', expected_request]:
        raise RuntimeError('S08 owner/request-id did not preserve Requested')
    if latest(text, 'REMOVE_REBOOT_S08_STATE') != 'requested':
        raise RuntimeError('second S08 state is not Requested')

    # The S08 evidence is checked before interacting with the second-boot shell.
    second_console_end = len(stream)
    send(b'\n')
    wait_text(rb'root@[^\n]*# ', 60, start_offset=second_console_end)
    verifier_start = len(stream)
    send(b'/usr/share/xkeen-lab-packages/remove-reboot-after-guest.sh\n')
    text = wait_text(rb'^REMOVE_REBOOT_AFTER_PASS=', 120, start_offset=verifier_start)
    if re.search(r'^REMOVE_REBOOT_AFTER_FAIL=', text, re.M):
        raise RuntimeError('after-boot verifier reported failure')
    for marker in (
        'REMOVE_PENDING_BASELINE=active-r3,real-history-json',
        'REMOVE_PENDING_HELPER_IDENTITY=PASS',
        'REMOVE_PENDING_LOCKS=RECOVERY_HELD_MUTATION_FREE',
        'REMOVE_PENDING_HELPER_STOPPED=PASS',
        'REMOVE_PENDING_REQUESTED=PASS',
        'REMOVE_PENDING_WAITER_INTERRUPTED=PASS',
        'REMOVE_PENDING_REQUEST_ID_STABLE=PASS',
        'REMOVE_PENDING_PAYLOAD_ABSENT=PASS',
        'REMOVE_PENDING_RECEIPT_UNCHANGED=PASS',
        'REMOVE_PENDING_CORE_ACTIVE_BEFORE_RESUME=PASS',
        'REMOVE_PENDING_DATA_PRESERVED=PASS',
        'REMOVE_PENDING_REBOOT_ARMED=PASS',
        'REMOVE_REBOOT_AFTER_SUPERVISOR=PASS',
        'REMOVE_REBOOT_AFTER_RECEIPT=remove/cleanup_complete',
        'REMOVE_REBOOT_AFTER_REQUEST_ID=' + expected_request,
        'REMOVE_REBOOT_AFTER_CORE_CGROUP=empty-or-absent',
        'REMOVE_REBOOT_AFTER_DATA=profile,history,asset,foreign-sentinel-PASS',
        'REMOVE_REBOOT_AFTER_PASS=boot-id-changed,auto-S09,remove-cleanup-complete,core-stopped,data-preserved',
    ):
        if not re.search(r'^' + re.escape(marker) + r'$', text, re.M):
            raise RuntimeError('missing guest success marker ' + marker)
    wait_text(rb'root@[^\n]*# ', 60, start_offset=verifier_start)
    send(b'poweroff -f\n')
    if drain_and_wait() != 0:
        raise RuntimeError('runner returned nonzero after guest poweroff')
except (OSError, TimeoutError, RuntimeError) as exc:
    error = str(exc)
finally:
    if process.poll() is None:
        process.send_signal(signal.SIGTERM)
        try:
            process.wait(timeout=55)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            error = (error or 'runner cleanup timeout') + '; runner group killed'
    selector.close()
    os.close(master)
    runner_output.close()

if error:
    tail = stream.decode('utf-8', 'replace')[-6000:]
    sys.stderr.write(tail)
    sys.exit(f'FAIL: {error}; serial={serial}; runner_log={runner_log}')
if not serial.is_file() or serial.stat().st_size > 2 * 1024 * 1024:
    sys.exit('FAIL: bounded serial log missing or oversized')
if runner_log.stat().st_size > 2 * 1024 * 1024:
    sys.exit('FAIL: bounded runner log oversized')
print('REMOVE_REBOOT_S08_REQUESTED_BEFORE_S09=PASS')
print('REMOVE_REBOOT_BOOT_ID_CHANGED=PASS')
print('REMOVE_REBOOT_AUTO_S09_CLEANUP=PASS')
print(f'REMOVE_REBOOT_SERIAL={serial}')
print(f'REMOVE_REBOOT_RUNNER_LOG={runner_log}')
