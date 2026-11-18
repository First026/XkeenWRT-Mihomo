#!/usr/bin/env python3
"""Фиксированная проверка наличия средств топологии в одноразовой VM."""
import os
import base64
import json
import pty
import re
import selectors
import signal
import subprocess
import sys
import time
from pathlib import Path

if sys.argv[1:]:
    sys.exit('usage: lifecycle-test.py')
arm = False
runner = Path(__file__).resolve().parent / 'run.sh'
master, slave = pty.openpty()
p = subprocess.Popen([str(runner)] + (['--arm64-baseline'] if arm else []),
                     stdin=slave, stdout=slave, stderr=slave, close_fds=True,
                     start_new_session=True)
os.close(slave)
sel = selectors.DefaultSelector()
sel.register(master, selectors.EVENT_READ)
start = time.monotonic()
output = bytearray()

def read_until(pattern, limit=420):
    segment = bytearray()
    deadline = min(start + 570, time.monotonic() + limit)
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

commands = (b"/usr/share/xkeen-lab-packages/manual-guest.sh\n",)
observed = []
error = None
try:
    read_until(rb'Please press Enter to activate this console\.', 90)
    os.write(master, b'\n')
    read_until(rb'root@[^\n]*# ')
    for line in commands:
        result = command(line)
        for item in result.splitlines():
            if item.startswith(('MANUAL_', 'LAB_RUNTIME_', 'LAB_HTTP_TRANSPORT=')):
                print(item)
                observed.append(item)
            if item == 'LAB_VETH=cleanup-failed':
                raise RuntimeError('не удалось удалить синтетический veth')
    if any(item.startswith(('MANUAL_FAIL:', 'LAB_RUNTIME_FAIL=')) for item in observed):
        fixture = Path('/tmp/xkeen-manual-frozen.cMSE4GYy/crates/profile-policy/tests/fixtures/effective-inline.json').read_text()
        encoded = base64.b64encode(json.dumps({'version': 1, 'config': fixture, 'assets': []}, separators=(',', ':')).encode())
        command(b'stty -echo\n')
        request_chunks = b'\n'.join(encoded[i:i+256] for i in range(0, len(encoded), 256))
        command(b"base64 -d > /tmp/xk-fixed-validator-request <<'XK_REQUEST'\n" + request_chunks + b"\nXK_REQUEST\n")
        probe = base64.b64encode(Path('/tmp/xk-fd-clone-probe').read_bytes())
        chunks = b'\n'.join(probe[i:i+256] for i in range(0, len(probe), 256))
        command(b"base64 -d > /tmp/xk-fd-clone-probe <<'XK_PROBE'\n" + chunks + b"\nXK_PROBE\n")
        command(b'chmod 700 /tmp/xk-fd-clone-probe\n')
        command(b'stty echo\n')
        for diagnostic in (
            b"/usr/libexec/xkeenwrt-integration/ipc-probe\n",
            b"/usr/libexec/xkeenwrt-integration/validator-probe\n",
            b"/usr/libexec/xkeenwrt/xkeenwrt-validate --cleanup >/tmp/xk-cleanup-result 2>/dev/null; printf 'DIAG_CLEAN_EXIT=%s\\n' \"$?\"\n",
            b"printf 'DIAG_CLEAN_STATUS='; jsonfilter -i /tmp/xk-cleanup-result -e '@.status'; true\n",
            b"printf 'DIAG_CLEAN_CODE='; jsonfilter -i /tmp/xk-cleanup-result -e '@.code'; true\n",
            b"/usr/libexec/xkeenwrt/xkeenwrt-validate </tmp/xk-fixed-validator-request >/tmp/xk-direct-result 2>/dev/null; printf 'DIAG_DIRECT_EXIT=%s\\n' \"$?\"\n",
            b"printf 'DIAG_DIRECT_STATUS='; jsonfilter -i /tmp/xk-direct-result -e '@.status'; true\n",
            b"printf 'DIAG_DIRECT_CODE='; jsonfilter -i /tmp/xk-direct-result -e '@.code'; true\n",
            b"b=$(jsonfilter -i /var/run/xkeenwrt/incarnation.json -e '@.boot_id'); p=$(jsonfilter -i /var/run/xkeenwrt/incarnation.json -e '@.pid'); t=$(jsonfilter -i /var/run/xkeenwrt/incarnation.json -e '@.starttime'); n=$(jsonfilter -i /var/run/xkeenwrt/incarnation.json -e '@.nonce'); /tmp/xk-fd-clone-probe /sys/fs/cgroup/xkeenwrt/incarnations/$b-$p-$t-$n\n",
            b"printf 'DIAG_FD_STATUS='; jsonfilter -i /tmp/xk-fd-clone-result -e '@.status'; true\n",
            b"printf 'DIAG_FD_CODE='; jsonfilter -i /tmp/xk-fd-clone-result -e '@.code'; true\n",
            b"printf 'DIAG_HTTP_CODE='; jsonfilter -i /tmp/xkeenwrt-body -e '@.code'; true\n",
            b"printf 'DIAG_HTTP_STATUS='; head -n 1 /tmp/xkeenwrt-response-clean; true\n",
            b"printf 'DIAG_SOCKET='; [ -S /var/run/xkeenwrt/control.sock ] && echo present || echo absent\n",
            b"ubus call service list '{\"name\":\"xkeenwrt-runtime\"}' > /tmp/xk-service\n",
            b"printf 'DIAG_RUNNING='; jsonfilter -i /tmp/xk-service -e '@[\"xkeenwrt-runtime\"].instances.*.running'; true\n",
            b"printf 'DIAG_EXIT='; jsonfilter -i /tmp/xk-service -e '@[\"xkeenwrt-runtime\"].instances.*.exit_code'; true\n",
            b"logread > /tmp/xkeen-diagnostic-log 2>/dev/null; true\n",
            b"grep -qi 'unsafe owned cgroup directory' /tmp/xkeen-diagnostic-log && echo DIAG_LOG_CLASS=CGROUP_MODE; true\n",
            b"grep -qi 'operation not permitted' /tmp/xkeen-diagnostic-log && echo DIAG_LOG_CLASS=EPERM; true\n",
            b"grep -qi 'permission denied' /tmp/xkeen-diagnostic-log && echo DIAG_LOG_CLASS=EACCES; true\n",
            b"grep -qi 'no such file or directory' /tmp/xkeen-diagnostic-log && echo DIAG_LOG_CLASS=ENOENT; true\n",
            b"grep -qi 'panicked' /tmp/xkeen-diagnostic-log && echo DIAG_LOG_CLASS=PANIC; true\n",
        ):
            for item in command(diagnostic).splitlines():
                if item.startswith('DIAG_'):
                    print(item, flush=True)
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

expected = ['LAB_RUNTIME_PASS=auth,save,validate,apply,control,stop,start',
            'MANUAL_PACKAGE_PASS=install,manual-start-stop,active-remove,rescue-retained,cleanup-complete']
if any(item not in observed for item in expected):
    sys.exit(f'FAIL: {observed!r}')
print('PASS: installed packages support manual runtime and rescue-backed removal')
