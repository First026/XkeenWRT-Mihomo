#!/usr/bin/env python3
"""Fixed read-only serial smoke test; --test-timeout exercises cleanup."""
import os
import pty
import re
import selectors
import signal
import subprocess
import sys
import time
from pathlib import Path

if sys.argv[1:] not in ([], ['--test-timeout']):
    sys.exit('usage: smoke.py [--test-timeout]')
deadline_seconds = 1 if sys.argv[1:] else 90
runner = Path(__file__).resolve().with_name('run.sh')
master, slave = pty.openpty()
process = subprocess.Popen([str(runner)], stdin=slave, stdout=slave, stderr=slave,
                           start_new_session=True, close_fds=True)
os.close(slave)
selector = selectors.DefaultSelector()
selector.register(master, selectors.EVENT_READ)
output = bytearray()
started = time.monotonic()
sent_enter = sent_probe = sent_poweroff = False
failure = None
probe = (b"printf '\\nLAB_RELEASE=%s|%s\\n' \"$(. /etc/openwrt_release; echo $DISTRIB_RELEASE)\" "
         b"\"$(. /etc/openwrt_release; echo $DISTRIB_REVISION)\"; "
         b"printf 'LAB_KERNEL=%s\\n' \"$(uname -r)\"; "
         b"printf 'LAB_PID1=%s\\n' \"$(cat /proc/1/comm)\"; "
         b"printf 'LAB_UBUS='; ubus call system board >/dev/null && echo ok || echo failed; "
         b"printf 'LAB_NET='; for i in /sys/class/net/*; do printf '%s ' \"${i##*/}\"; done; echo; "
         b"printf 'LAB_CGROUP='; cat /sys/fs/cgroup/cgroup.controllers; echo LAB_DONE\n")
try:
    while True:
        if time.monotonic() - started > deadline_seconds:
            raise TimeoutError(f'smoke deadline {deadline_seconds}s exceeded')
        for key, _ in selector.select(timeout=0.2):
            try:
                chunk = os.read(key.fd, 4096)
            except OSError:
                chunk = b''
            if chunk:
                output.extend(chunk)
                if len(output) > 262144:
                    raise RuntimeError('serial output exceeded 256 KiB')
        text = output.decode('utf-8', 'replace').replace('\r', '')
        if not sent_enter and 'Please press Enter to activate this console.' in text:
            os.write(master, b'\n')
            sent_enter = True
        if sent_enter and not sent_probe and re.search(r'root@[^\n]*# ', text):
            os.write(master, probe)
            sent_probe = True
        if sent_probe and not sent_poweroff and re.search(r'^LAB_DONE$', text, re.M):
            checks = [r'^LAB_RELEASE=25\.12\.6\|r33311-981c978eff$',
                      r'^LAB_KERNEL=6\.12\.112$', r'^LAB_PID1=procd$',
                      r'^LAB_UBUS=ok$', r'^LAB_NET=lo *$']
            for check in checks:
                if not re.search(check, text, re.M):
                    raise RuntimeError(f'missing expected result: {check}')
            match = re.search(r'^LAB_CGROUP=(.*)$', text, re.M)
            if not match or not {'cpu', 'memory', 'pids'} <= set(match.group(1).split()):
                raise RuntimeError('expected cpu, memory and pids cgroup controllers')
            os.write(master, b'poweroff -f\n')
            sent_poweroff = True
        code = process.poll()
        if code is not None:
            if not sent_poweroff or code != 0:
                raise RuntimeError(f'runner exited unexpectedly: {code}')
            print('PASS: OpenWrt 25.12.6 r33311-981c978eff, kernel 6.12.112, procd/ubus, lo only, cgroup cpu/memory/pids')
            break
except (TimeoutError, RuntimeError, OSError) as exc:
    failure = str(exc)
finally:
    if process.poll() is None:
        process.send_signal(signal.SIGTERM)
        try:
            process.wait(timeout=55)
            if process.returncode == 1:
                failure = (failure or 'runner failed') + '; runner reported cleanup failure'
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            failure = (failure or 'runner failed to exit') + '; forced runner termination; cleanup unverified'
    selector.close()
    os.close(master)
if failure:
    print('FAIL:', failure, file=sys.stderr)
    print(output[-4096:].decode('utf-8', 'replace'), file=sys.stderr)
    sys.exit(1)
