#!/usr/bin/env python3
"""Фиксированные тесты протокола валидатора в одноразовой VM."""
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
    sys.exit('usage: runtime-test.py')
runner = Path(__file__).resolve().with_name('run-runtime.sh')
master, slave = pty.openpty()
p = subprocess.Popen([str(runner)],
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

identity = (b"printf 'LAB_IDENT=%s|%s|%s\\n' \"$(uname -m)\" \"$(uname -r)\" \"$(. /etc/openwrt_release; echo $DISTRIB_REVISION)\"\n"
            b"printf 'LAB_PID1=%s\\n' \"$(cat /proc/1/comm)\"\n"
            b"printf 'LAB_NET='; for i in /sys/class/net/*; do printf '%s ' \"${i##*/}\"; done; echo\n"
            b"printf 'LAB_UBUS='; ubus call system board >/dev/null && echo ok || echo failed\n"
            b"printf 'LAB_MARKER='; cat /etc/xkeenwrt-isolation-lab\n"
            b"printf 'test-sentinel-v1\\n' > /tmp/xkeenwrt-test-sentinel\n")
commands = identity.splitlines(keepends=True)
error = None
try:
    read_until(rb'Please press Enter to activate this console\.', 90)
    os.write(master, b'\n')
    read_until(rb'root@[^\n]*# ')
    for line in commands:
        result = command(line)
        if b"LAB_IDENT=" in line and not re.search(r'^LAB_IDENT=x86_64\|6\.12\.112\|r33311-981c978eff$', result, re.M):
            raise RuntimeError('неверная идентификация гостя')
        for label, expected in (('LAB_PID1', 'procd'), ('LAB_NET', 'lo '), ('LAB_UBUS', 'ok'), ('LAB_MARKER', 'xkeenwrt-validator-lab-v1')):
            if (label + '=').encode() in line and not re.search('^' + label + '=' + re.escape(expected) + '$', result, re.M):
                raise RuntimeError('неверный признак гостя: ' + label)
    command(b"sed -i '/procd_set_param command.* runtime/a\\    procd_set_param stderr 1' /etc/init.d/xkeenwrt-runtime\n")
    result = command(b"/usr/libexec/xkeenwrt-integration/runtime-smoke.sh; printf 'LAB_SCRIPT_STATUS=%s\\n' \"$?\"\n")
    if not re.search(r'^LAB_RUNTIME_PASS=auth,save,validate,apply,control,stop,start$', result, re.M) or not re.search(r'^LAB_SCRIPT_STATUS=0$', result, re.M):
        failure = re.search(r'^LAB_RUNTIME_FAIL=([a-z]+)$', result, re.M)
        if 'nc: invalid option' in result or 'nc: unrecognized option' in result:
            print('LAB_DEBUG_NC_OPTION=invalid', file=sys.stderr)
        for probe in (
            b"printf 'LAB_DEBUG_TOKEN='; [ -s /etc/xkeenwrt/bootstrap-token ] && echo yes || echo no\n",
            b"printf 'LAB_DEBUG_SOCKET='; [ -S /var/run/xkeenwrt/control.sock ] && echo yes || echo no\n",
            b"printf 'LAB_DEBUG_PROCESS='; pidof xkeenwrt-ui >/dev/null && echo yes || echo no\n",
            b"/usr/bin/xkeenwrt-ui >/dev/null 2>/tmp/xkeenwrt-exec-error; printf 'LAB_DEBUG_EXEC=%s\\n' \"$?\"\n",
            b"printf 'LAB_DEBUG_EXECERR='; if grep -qi 'not found' /tmp/xkeenwrt-exec-error; then echo notfound; elif grep -qi 'permission denied' /tmp/xkeenwrt-exec-error; then echo permission; elif grep -qi 'usage:' /tmp/xkeenwrt-exec-error; then echo usage; else echo other; fi\n",
            b"printf 'LAB_DEBUG_UBUS='; ubus list service >/dev/null && echo yes || echo no\n",
            b"printf 'LAB_DEBUG_LOG='; if logread 2>/dev/null | grep -Fq 'Cannot drop a runtime in a context where blocking is not allowed'; then echo tokio_drop; elif logread 2>/dev/null | grep -qi 'segfault'; then echo segv; elif logread 2>/dev/null | grep -qi 'out of memory'; then echo oom; elif logread 2>/dev/null | grep -qi 'panic'; then echo panic; else echo other; fi\n",
            b"printf 'LAB_DEBUG_EXIT='; ubus call service list '{\"name\":\"xkeenwrt-runtime\"}' | jsonfilter -e '@[\"xkeenwrt-runtime\"].instances.*.exit_code' | tr '\\n' ' '; echo\n",
            b"printf 'LAB_DEBUG_CORE='; [ -d /sys/fs/cgroup/xkeenwrt/core ] && echo yes || echo no\n",
            b"printf 'LAB_DEBUG_HTTP='; sed -n '1s/^HTTP\\/[^ ]* \\([0-9][0-9][0-9]\\).*/\\1/p' /tmp/xkeenwrt-response-clean 2>/dev/null\n",
            b"printf 'LAB_DEBUG_CODE='; jsonfilter -i /tmp/xkeenwrt-body -e '@.code' 2>/dev/null; echo\n",
            b"printf 'LAB_DEBUG_COOKIE='; grep -qi '^set-cookie: session_id=' /tmp/xkeenwrt-response-clean 2>/dev/null && echo yes || echo no\n",
            b"printf 'LAB_DEBUG_RESPONSE='; [ -s /tmp/xkeenwrt-response ] && echo yes || echo no\n",
            b"printf 'LAB_DEBUG_NC='; nc -h 2>&1 | grep -q -- '-w' && echo yes || echo no\n",
            b"printf 'GET /api/auth/login HTTP/1.0\\r\\nHost: 127.0.0.1:1000\\r\\n\\r\\n' | nc 127.0.0.1 1000 > /tmp/xkeenwrt-ncprobe 2>/tmp/xkeenwrt-ncerr; printf 'LAB_DEBUG_NCRC=%s\\n' \"$?\"\n",
            b"printf 'LAB_DEBUG_NCDATA='; [ -s /tmp/xkeenwrt-ncprobe ] && echo yes || echo no\n",
            b"printf 'LAB_DEBUG_NCERR='; if grep -qi refused /tmp/xkeenwrt-ncerr; then echo refused; elif [ -s /tmp/xkeenwrt-ncerr ]; then echo other; else echo none; fi\n",
            b"printf 'LAB_DEBUG_UI='; ubus call service list '{\"name\":\"xkeenwrt-ui\"}' | jsonfilter -e '@[\"xkeenwrt-ui\"].instances.*.running' | tr '\\n' ' '; echo\n",
            b"printf 'LAB_DEBUG_RUNTIME='; ubus call service list '{\"name\":\"xkeenwrt-runtime\"}' | jsonfilter -e '@[\"xkeenwrt-runtime\"].instances.*.running' | tr '\\n' ' '; echo\n",
        ):
            for item in command(probe).splitlines():
                if re.fullmatch(r'LAB_DEBUG_[A-Z]+=(?:yes|no|true|false|notfound|permission|usage|other|refused|none|segv|oom|panic|tokio_drop|[0-9]+|[0-9]+ |[A-Z_]+| *|true |false )', item):
                    print(item, file=sys.stderr)
        raise RuntimeError('runtime smoke не прошёл на этапе ' + (failure.group(1) if failure else 'неизвестно'))
    os.write(master, b'poweroff -f\n')
    try:
        p.wait(timeout=20)
    except subprocess.TimeoutExpired:
        raise RuntimeError('poweroff не завершился')
    if p.returncode:
        raise RuntimeError(f'ошибка runner: {p.returncode}')
    print('PASS: procd, HTTP, validation, apply, stop/start и poweroff')
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
