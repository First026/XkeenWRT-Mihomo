#!/usr/bin/env python3
"""Exercise the fixed validator scenarios inside the disposable OpenWrt VM."""
import os
import pty
import re
import selectors
import signal
import subprocess
import sys
import time
from pathlib import Path

if sys.argv[1:] not in ([], ['--test-missing-executable'], ['--test-timeout'],
                         ['--arm64'], ['--arm64', '--test-guard'], ['--arm64', '--test-probe'], ['--arm64', '--test-missing-executable'], ['--arm64', '--test-timeout']):
    sys.exit('usage: isolation.py [--arm64] [--test-guard|--test-probe|--test-missing-executable|--test-timeout]')
arm64 = '--arm64' in sys.argv[1:]
missing_test = '--test-missing-executable' in sys.argv[1:]
timeout_test = '--test-timeout' in sys.argv[1:]
probe_test = '--test-probe' in sys.argv[1:]
guard_test = '--test-guard' in sys.argv[1:]
runner = Path(__file__).resolve().with_name('run.sh')
master, slave = pty.openpty()
runner_mode = (['--arm64-baseline'] if missing_test else ['--arm64']) if arm64 else ([] if missing_test else ['--isolation'])
process = subprocess.Popen([str(runner)] + runner_mode, stdin=slave, stdout=slave,
                           stderr=slave, start_new_session=True, close_fds=True)
os.close(slave)
selector = selectors.DefaultSelector()
selector.register(master, selectors.EVENT_READ)
output = bytearray()
started = time.monotonic()
phase_started = started
phase = 'boot'
failure = None
scenario_failure = None
scenarios = ('probe', 'timeout', 'output', 'tmpfs', 'pids', 'memory', 'setup-denied', 'mihomo-valid', 'mihomo-invalid', 'mihomo-invalid-unreadable', 'mihomo-missing-asset', 'mihomo-file-contained', 'mihomo-file-escape', 'mihomo-awg-v3', 'mihomo-awg-legacy')
if probe_test:
    scenarios = ('probe',)
scenario_index = 0
memory_peak = None
core_peaks = {}
# No scenario or path is accepted from the caller.
identity = (b"printf '\\nLAB_RELEASE=%s|%s\\n' \"$(. /etc/openwrt_release; echo $DISTRIB_RELEASE)\" \"$(. /etc/openwrt_release; echo $DISTRIB_REVISION)\"\n"
            b"printf 'LAB_KERNEL=%s\\n' \"$(uname -r)\"\n"
            b"printf 'LAB_ARCH=%s\\n' \"$(uname -m)\"\n"
            b"printf 'LAB_TARGET=%s\\n' \"$(. /etc/openwrt_release; echo $DISTRIB_TARGET)\"\n"
            b"printf 'LAB_PID1=%s\\n' \"$(cat /proc/1/comm)\"\n"
            b"printf 'LAB_UBUS='; ubus call system board >/dev/null && echo ok || echo failed\n"
            b"printf 'LAB_NET='; for i in /sys/class/net/*; do printf '%s ' \"${i##*/}\"; done; echo\n"
            b"printf 'LAB_MARKER='; cat /etc/xkeenwrt-isolation-lab\n"
            b"printf 'LAB_CMDLINE='; cat /proc/cmdline\n"
            b"printf 'xkeenwrt-sentinel-v1\\n' > /tmp/xkeenwrt-isolation-sentinel; echo LAB_ID_DONE\n")
if not missing_test:
    identity = identity.replace(b"echo LAB_ID_DONE\n", b"cp /usr/libexec/xkeenwrt-lab/synthetic-ed25519-key.pem /tmp/xkeenwrt-isolation-key.pem; chmod 644 /tmp/xkeenwrt-isolation-key.pem\n"
                                b"printf 'LAB_KEY='; sha256sum /tmp/xkeenwrt-isolation-key.pem | cut -d ' ' -f1\n"
                                b"printf 'LAB_KEY_MODE='; ls -l /tmp/xkeenwrt-isolation-key.pem | cut -c1-10; echo LAB_ID_DONE\n")

guard = (b"state=clean; [ ! -e /tmp/xkeenwrt-lab.lock ] || state=dirty; for p in /tmp/xkeenwrt-lab-* /sys/fs/cgroup/xkeenwrt-lab-*; do [ ! -e \"$p\" ] || state=dirty; done; echo LAB_GUARD_BEFORE=$state\n"
         b"rm /etc/xkeenwrt-isolation-lab\n"
         b"/usr/libexec/xkeenwrt-lab/isolation-lab probe; printf 'LAB_GUARD_STATUS=%s\\n' \"$?\"\n"
         b"state=clean; [ ! -e /tmp/xkeenwrt-lab.lock ] || state=dirty; for p in /tmp/xkeenwrt-lab-* /sys/fs/cgroup/xkeenwrt-lab-*; do [ ! -e \"$p\" ] || state=dirty; done; echo LAB_GUARD_AFTER=$state; echo LAB_GUARD_DONE\n")

def scenario_command(name):
    # Names come only from the fixed tuple above.
    if missing_test:
        return (b"if test -x /usr/libexec/xkeenwrt-lab/isolation-lab; then echo LAB_UNEXPECTED; "
                b"else echo LAB_MISSING; fi; echo LAB_PROBE_DONE\n")
    return (b"/usr/libexec/xkeenwrt-lab/isolation-lab " + name.encode('ascii') +
            b"; printf 'LAB_STATUS=%s\\n' \"$?\"; echo LAB_PROBE_DONE\n")

final = (b"printf 'LAB_FINAL_PID1=%s\\n' \"$(cat /proc/1/comm)\"\n"
         b"printf 'LAB_FINAL_UBUS='; ubus call system board >/dev/null && echo ok || echo failed\n"
         b"printf 'LAB_FINAL_NET='; for i in /sys/class/net/*; do printf '%s ' \"${i##*/}\"; done; echo\n"
         b"printf 'LAB_SENTINEL='; cat /tmp/xkeenwrt-isolation-sentinel\n")
if not missing_test:
    final += (b"printf 'LAB_FINAL_KEY='; sha256sum /tmp/xkeenwrt-isolation-key.pem | cut -d ' ' -f1\n"
              b"printf 'LAB_FINAL_KEY_MODE='; ls -l /tmp/xkeenwrt-isolation-key.pem | cut -c1-10\n")
final += b"echo LAB_FINAL_DONE\n"

def send(command, new_phase):
    global phase, phase_started, output
    output.clear()
    for line in command.splitlines(keepends=True):
        for start in range(0, len(line), 64):
            os.write(master, line[start:start + 64])
            time.sleep(0.05)
        # Boot's Enter and poweroff intentionally do not return a shell prompt.
        if new_phase in ('shell', 'poweroff'):
            continue
        pending = bytearray()
        line_started = time.monotonic()
        while not re.search(rb'root@[^\r\n]*# ', pending):
            if time.monotonic() - line_started > 40 or time.monotonic() - started > 165:
                raise TimeoutError('deadline awaiting shell prompt in ' + new_phase)
            for key, _ in selector.select(timeout=0.2):
                try:
                    chunk = os.read(key.fd, 4096)
                except OSError:
                    chunk = b''
                pending.extend(chunk)
                output.extend(chunk)
                if len(output) > 262144:
                    raise RuntimeError('serial output exceeded 256 KiB')
            if process.poll() is not None:
                raise RuntimeError('runner exited awaiting shell prompt')
    phase, phase_started = new_phase, time.monotonic()

def require(pattern, text):
    if not re.search(pattern, text, re.M):
        raise RuntimeError('missing expected result: ' + pattern)

try:
    while True:
        now = time.monotonic()
        if now - started > (1 if timeout_test else 165) or now - phase_started > (90 if phase == 'boot' else 45):
            raise TimeoutError('deadline exceeded in ' + phase)
        for key, _ in selector.select(timeout=0.2):
            try:
                chunk = os.read(key.fd, 4096)
            except OSError:
                chunk = b''
            output.extend(chunk)
            if len(output) > 262144:
                raise RuntimeError('serial output exceeded 256 KiB')
        text = output.decode('utf-8', 'replace').replace('\r', '')
        if phase == 'boot' and 'Please press Enter to activate this console.' in text:
            send(b'\n', 'shell')
        elif phase == 'shell' and re.search(r'root@[^\n]*# ', text):
            send(identity, 'identity')
        elif phase == 'identity' and re.search(r'^LAB_ID_DONE$', text, re.M):
            for pattern in (r'^LAB_RELEASE=25\.12\.6\|r33311-981c978eff$', r'^LAB_KERNEL=6\.12\.112$',
                            r'^LAB_PID1=procd$', r'^LAB_UBUS=ok$', r'^LAB_NET=lo *$',
                            ) + (() if missing_test else (r'^LAB_MARKER=xkeenwrt-validator-lab-v1$',
                            r'^LAB_CMDLINE=.*\bxkeenwrt\.isolation_lab=1\b',
                            r'^LAB_KEY=c4932a9b6b97423b249a53e58d706f820185467464699038ed7ca5b29815ba03$', r'^LAB_KEY_MODE=-rw-r--r--$')):
                require(pattern, text)
            if arm64:
                require(r'^LAB_ARCH=aarch64$', text)
                require(r'^LAB_TARGET=armsr/armv8$', text)
            if guard_test:
                send(guard, 'guard')
            else:
                send(scenario_command(scenarios[scenario_index]), 'probe')
        elif phase == 'guard' and re.search(r'^LAB_GUARD_DONE$', text, re.M):
            for pattern in (r'^LAB_GUARD_BEFORE=clean$', r'^LAB_GUARD_AFTER=clean$',
                            r'^\{"scenario":"probe","result":"unavailable"\}$', r'^LAB_GUARD_STATUS=1$'):
                require(pattern, text)
            send(final, 'final')
        elif phase == 'probe' and re.search(r'^LAB_PROBE_DONE$', text, re.M):
            if missing_test:
                require(r'^LAB_MISSING$', text)
            elif scenarios[scenario_index] == 'mihomo-invalid-unreadable':
                if not (re.search(r'^\{"scenario":"mihomo-invalid-unreadable","result":"unavailable","reason":"core-invalid-evidence"\}$', text, re.M)
                        and re.search(r'^LAB_STATUS=1$', text, re.M)):
                    if (re.search(r'^\{"scenario":"mihomo-invalid-unreadable","result":"pass","memory_peak_bytes":[1-9][0-9]{0,11}\}$', text, re.M)
                            and re.search(r'^LAB_STATUS=0$', text, re.M)):
                        scenario_failure = 'mihomo-invalid-unreadable was incorrectly accepted as a parse rejection'
                    else:
                        scenario_failure = 'mihomo-invalid-unreadable did not refuse for missing parse evidence'
            elif (unavailable := re.search(
                    r'^\{"scenario":"' + scenarios[scenario_index] + r'","result":"unavailable"(?:,"reason":"(setup|execute|cleanup|core-cpu|core-exit-0|core-exit-1|core-exit-other|core-timeout|core-output|core-handshake|core-oom|core-missing-evidence|core-file-evidence|core-invalid-evidence|core-pids|core-unexpected-parse)")?\}$', text, re.M)) and re.search(r'^LAB_STATUS=1$', text, re.M):
                scenario_failure = scenarios[scenario_index] + ' returned unavailable' + (': ' + unavailable.group(1) if unavailable.group(1) else '')
            elif scenarios[scenario_index] == 'memory' or scenarios[scenario_index].startswith('mihomo-'):
                match = re.search(r'^\{"scenario":"' + scenarios[scenario_index] + r'","result":"pass","memory_peak_bytes":([1-9][0-9]{0,11})\}$', text, re.M)
                if not match or not re.search(r'^LAB_STATUS=0$', text, re.M):
                    scenario_failure = scenarios[scenario_index] + ' returned an unexpected result or status'
                else:
                    if scenarios[scenario_index] == 'memory':
                        memory_peak = int(match.group(1))
                    else:
                        core_peaks[scenarios[scenario_index]] = int(match.group(1))
            elif not (re.search(r'^\{"scenario":"' + scenarios[scenario_index] + r'","result":"pass"\}$', text, re.M)
                      and re.search(r'^LAB_STATUS=0$', text, re.M)):
                scenario_failure = scenarios[scenario_index] + ' returned an unexpected result or status'
            send(final, 'final')
        elif phase == 'final' and re.search(r'^LAB_FINAL_DONE$', text, re.M):
            for pattern in (r'^LAB_FINAL_PID1=procd$', r'^LAB_FINAL_UBUS=ok$', r'^LAB_FINAL_NET=lo *$',
                            r'^LAB_SENTINEL=xkeenwrt-sentinel-v1$') + (() if missing_test else (
                            r'^LAB_FINAL_KEY=c4932a9b6b97423b249a53e58d706f820185467464699038ed7ca5b29815ba03$', r'^LAB_FINAL_KEY_MODE=-rw-r--r--$')):
                require(pattern, text)
            if not missing_test and not guard_test and not scenario_failure and scenario_index + 1 < len(scenarios):
                scenario_index += 1
                send(scenario_command(scenarios[scenario_index]), 'probe')
            else:
                send(b'poweroff -f\n', 'poweroff')
        code = process.poll()
        if code is not None:
            if phase != 'poweroff' or code != 0:
                raise RuntimeError(f'runner exited unexpectedly in {phase}: {code}')
            if scenario_failure:
                failure = scenario_failure
            else:
                if missing_test:
                    print('PASS: missing executable rejected in baseline guest')
                elif guard_test:
                    print('PASS: missing marker refused before job resources')
                elif probe_test:
                    print('PASS: isolated guest probe and integrity checks')
                else:
                    print(f'PASS: isolated guest fixed scenarios with integrity checks; memory peak {memory_peak} bytes; Mihomo peaks {core_peaks} bytes')
            break
except (TimeoutError, RuntimeError, OSError) as exc:
    failure = str(exc)
finally:
    if process.poll() is None:
        process.send_signal(signal.SIGTERM)
        try:
            process.wait(timeout=55)
            if process.returncode == 1:
                failure = (failure or 'runner failed') + '; runner exited with status 1 during cleanup'
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            failure = (failure or 'runner failed to exit') + '; forced runner termination; cleanup unverified'
    selector.close()
    os.close(master)
if failure:
    # Never publish potentially untrusted executable output.
    print('FAIL:', failure, file=sys.stderr)
    sys.exit(1)
