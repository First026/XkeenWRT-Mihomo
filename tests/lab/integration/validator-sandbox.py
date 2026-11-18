#!/usr/bin/env python3
"""Фиксированные тесты guardian и изоляции валидатора в одноразовой VM."""
import os
import json
import shlex
import pty
import re
import selectors
import signal
import subprocess
import sys
import time
from pathlib import Path

if sys.argv[1:] not in ([], ['--arm64']):
    sys.exit('usage: validator-sandbox.py [--arm64]')
arm = bool(sys.argv[1:])
runner = Path(__file__).resolve().with_name('run-validator-arm64.sh' if arm else 'run-validator.sh')
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
    deadline = min(start + (290 if arm else 165), time.monotonic() + limit)
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
        if b"LAB_IDENT=" in line and not re.search(r'^LAB_IDENT=' + ('aarch64' if arm else 'x86_64') + r'\|6\.12\.112\|r33311-981c978eff$', result, re.M):
            raise RuntimeError('неверная идентификация гостя')
        for label, expected in (('LAB_PID1', 'procd'), ('LAB_NET', 'lo '), ('LAB_UBUS', 'ok'), ('LAB_MARKER', 'xkeenwrt-validator-lab-v1')):
            if (label + '=').encode() in line and not re.search('^' + label + '=' + re.escape(expected) + '$', result, re.M):
                raise RuntimeError('неверный признак гостя: ' + label)
    guard_line = b"/usr/libexec/xkeenwrt/xkeenwrt-validate < /usr/libexec/xkeenwrt-integration/requests/valid.json; printf 'LAB_GUARD_EXIT=%s\\n' \"$?\"\n"
    result = command(guard_line)
    if not re.search(r'^\{\"status\":\"unavailable\",\"code\":\"SANDBOX_UNAVAILABLE\"\}$', result, re.M) or not re.search(r'^LAB_GUARD_EXIT=0$', result, re.M):
        raise RuntimeError('отсутствующий deployment marker не вызвал отказ')
    result = command(b"printf 'LAB_GUARD_CLEAN='; [ ! -e /tmp/xkeenwrt-validation ] && [ ! -e /sys/fs/cgroup/xkeenwrt-validation ] && echo ok || echo failed\n")
    if not re.search(r'^LAB_GUARD_CLEAN=ok$', result, re.M):
        raise RuntimeError('guard создал ресурсы до разрешения')
    print('PASS: отсутствие deployment marker', flush=True)
    for line in (
        b"mkdir /sys/fs/cgroup/xkeenwrt-validation\n",
        b"printf '+memory +pids' > /sys/fs/cgroup/cgroup.subtree_control\n",
        b"printf '+memory +pids' > /sys/fs/cgroup/xkeenwrt-validation/cgroup.subtree_control\n",
        b"printf 'xkeenwrt-validation-v1\\n' > /etc/xkeenwrt-validator-enabled; chmod 600 /etc/xkeenwrt-validator-enabled\n",
    ):
        command(line)
    result = command(b"printf 'LAB_SETUP='; [ -d /sys/fs/cgroup/xkeenwrt-validation ] && grep -q memory /sys/fs/cgroup/xkeenwrt-validation/cgroup.subtree_control && grep -q pids /sys/fs/cgroup/xkeenwrt-validation/cgroup.subtree_control && test -f /etc/xkeenwrt-validator-enabled && echo ok || echo failed\n")
    if not re.search(r'^LAB_SETUP=ok$', result, re.M):
        raise RuntimeError('подготовка cgroup/marker не прошла')
    # Проверяем deployment guard до запуска обычной матрицы.
    for name, prepare in (
        ('bad-content', "printf 'bad\\n' > /etc/xkeenwrt-validator-enabled; chmod 600 /etc/xkeenwrt-validator-enabled"),
        ('bad-mode', "printf 'xkeenwrt-validation-v1\\n' > /etc/xkeenwrt-validator-enabled; chmod 644 /etc/xkeenwrt-validator-enabled"),
    ):
        command((prepare + "\n").encode())
        result = command(b"/usr/libexec/xkeenwrt/xkeenwrt-validate-production < /usr/libexec/xkeenwrt-integration/requests/valid.json; echo LAB_GUARD_DONE\n")
        if not re.search(r'^\{"status":"unavailable","code":"SANDBOX_UNAVAILABLE"\}$', result, re.M):
            raise RuntimeError(name + ': отсутствует отказ guard')
        result = command(b"printf 'LAB_CLEAN='; [ ! -e /tmp/xkeenwrt-validation/job ] && [ ! -e /sys/fs/cgroup/xkeenwrt-validation/job ] && echo ok || echo failed\n")
        if not re.search(r'^LAB_CLEAN=ok$', result, re.M):
            raise RuntimeError(name + ': обнаружены ресурсы задания')
        print('PASS: guard ' + name, flush=True)
    command(b"printf 'xkeenwrt-validation-v1\\n' > /etc/xkeenwrt-validator-enabled; chmod 600 /etc/xkeenwrt-validator-enabled\n")
    command(b"mv /etc/xkeenwrt-isolation-lab /etc/xkeenwrt-isolation-lab.saved\n")
    for name, prefix, binary in (
        ('production-without-lab-marker', '', 'xkeenwrt-validate-production'),
        ('fault-ignored-without-lab-marker', 'XKEENWRT_VALIDATOR_LAB_FAULT=before-admission ', 'xkeenwrt-validate'),
    ):
        line = (prefix + '/usr/libexec/xkeenwrt/' + binary + ' < /usr/libexec/xkeenwrt-integration/requests/valid.json; echo LAB_GUARD_DONE\n').encode()
        result = command(line)
        if not re.search(r'^\{"status":"valid","code":"VALID"\}$', result, re.M):
            raise RuntimeError(name + ': отсутствует ожидаемый VALID')
        result = command(b"printf 'LAB_CLEAN='; [ ! -e /tmp/xkeenwrt-validation/job ] && [ ! -e /sys/fs/cgroup/xkeenwrt-validation/job ] && echo ok || echo failed\n")
        if not re.search(r'^LAB_CLEAN=ok$', result, re.M):
            raise RuntimeError(name + ': ресурсы задания не очищены')
        print('PASS: ' + name, flush=True)
    command(b"mv /etc/xkeenwrt-isolation-lab.saved /etc/xkeenwrt-isolation-lab\n")
    cases = (
        ('valid-lab', 'valid', '', 'valid', 'VALID', 'xkeenwrt-validate'),
        ('valid-production', 'valid', '', 'valid', 'VALID', 'xkeenwrt-validate-production'),
        ('vless', 'vless', '', 'valid', 'VALID', 'xkeenwrt-validate'),
        ('provider', 'provider', '', 'valid', 'VALID', 'xkeenwrt-validate'),
        ('provider-missing', 'provider-missing', '', 'unavailable', 'ASSETS_UNVERIFIED', 'xkeenwrt-validate'),
        ('rule-provider', 'rule-provider', '', 'valid', 'VALID', 'xkeenwrt-validate'),
        ('rule-provider-missing', 'rule-provider-missing', '', 'unavailable', 'ASSETS_UNVERIFIED', 'xkeenwrt-validate'),
        ('invalid', 'invalid', '', 'invalid', 'INVALID_CONFIG', 'xkeenwrt-validate'),
        ('missing', 'missing', '', 'unavailable', 'CORE_UNAVAILABLE', 'xkeenwrt-validate'),
        ('before-admission', 'valid', 'before-admission', 'unavailable', 'WORKER_FAILED', 'xkeenwrt-validate'),
        ('after-admission', 'valid', 'after-admission', 'unavailable', 'WORKER_FAILED', 'xkeenwrt-validate'),
        ('after-release', 'valid', 'after-release', 'unavailable', 'WORKER_FAILED', 'xkeenwrt-validate'),
        ('after-detached', 'valid', 'after-detached', 'unavailable', 'WORKER_FAILED', 'xkeenwrt-validate'),
    )
    for name, fixture, fault, status, code, binary in cases:
        prefix = 'XKEENWRT_VALIDATOR_LAB_FAULT=' + shlex.quote(fault) + ' ' if fault else ''
        line = (prefix + '/usr/libexec/xkeenwrt/' + binary + ' < /usr/libexec/xkeenwrt-integration/requests/' + fixture +
                '.json; printf "LAB_EXIT=%s\\n" "$?"; echo LAB_SCENARIO_DONE\n').encode()
        result = command(line)
        expected = json.dumps({'status': status, 'code': code}, separators=(',', ':'))
        if not re.search('^' + re.escape(expected) + '$', result, re.M) or not re.search(r'^LAB_EXIT=0$', result, re.M):
            observed = re.findall(r'^\{"status":"(?:valid|invalid|unavailable)","code":"[A-Z_]+"\}$', result, re.M)
            raise RuntimeError(name + ': неожиданный фиксированный ответ ' + (observed[-1] if observed else '(нет)'))
        result = command(b"printf 'LAB_CLEAN='; [ ! -e /tmp/xkeenwrt-validation/job ] && [ ! -e /sys/fs/cgroup/xkeenwrt-validation/job ] && echo ok || echo failed\n")
        if not re.search(r'^LAB_CLEAN=ok$', result, re.M):
            raise RuntimeError(name + ': ресурсы задания не очищены')
        for line, pattern in (
            (b"printf 'LAB_FINAL_PID1=%s\\n' \"$(cat /proc/1/comm)\"\n", r'^LAB_FINAL_PID1=procd$'),
            (b"printf 'LAB_FINAL_UBUS='; ubus call system board >/dev/null && echo ok || echo failed\n", r'^LAB_FINAL_UBUS=ok$'),
            (b"printf 'LAB_FINAL_NET='; for i in /sys/class/net/*; do printf '%s ' \"${i##*/}\"; done; echo\n", r'^LAB_FINAL_NET=lo *$'),
            (b"printf 'LAB_SENTINEL='; cat /tmp/xkeenwrt-test-sentinel\n", r'^LAB_SENTINEL=test-sentinel-v1$'),
        ):
            if not re.search(pattern, command(line), re.M):
                raise RuntimeError(name + ': проверка целостности не прошла')
        print('PASS:', name, flush=True)
    crash = (b"XKEENWRT_VALIDATOR_LAB_FAULT=guardian-crash-detached /usr/libexec/xkeenwrt/xkeenwrt-validate "
             b"< /usr/libexec/xkeenwrt-integration/requests/valid.json; printf 'LAB_CRASH_EXIT=%s\\n' \"$?\"\n")
    result = command(crash)
    if not re.search(r'^LAB_CRASH_EXIT=117$', result, re.M):
        raise RuntimeError('guardian-crash: ожидаемое завершение 117 не подтверждено')
    result = command(b"printf 'LAB_STALE='; [ -d /tmp/xkeenwrt-validation/job ] && grep -qx 'populated 1' /sys/fs/cgroup/xkeenwrt-validation/job/cgroup.events && echo yes || echo no\n")
    if not re.search(r'^LAB_STALE=yes$', result, re.M):
        raise RuntimeError('guardian-crash: живое оставленное задание не подтверждено')
    recover = (b"/usr/libexec/xkeenwrt/xkeenwrt-validate < /usr/libexec/xkeenwrt-integration/requests/valid.json; "
               b"printf 'LAB_RECOVER_EXIT=%s\\n' \"$?\"\n")
    result = command(recover)
    if not re.search(r'^\{"status":"valid","code":"VALID"\}$', result, re.M) or not re.search(r'^LAB_RECOVER_EXIT=0$', result, re.M):
        raise RuntimeError('guardian-crash: следующий запуск не восстановился')
    result = command(b"printf 'LAB_RECOVER_CLEAN='; [ ! -e /tmp/xkeenwrt-validation/job ] && [ ! -e /sys/fs/cgroup/xkeenwrt-validation/job ] && echo ok || echo failed\n")
    if not re.search(r'^LAB_RECOVER_CLEAN=ok$', result, re.M):
        raise RuntimeError('guardian-crash: оставленное задание не очищено')
    for line, pattern in (
        (b"printf 'LAB_FINAL_PID1=%s\\n' \"$(cat /proc/1/comm)\"\n", r'^LAB_FINAL_PID1=procd$'),
        (b"printf 'LAB_FINAL_UBUS='; ubus call system board >/dev/null && echo ok || echo failed\n", r'^LAB_FINAL_UBUS=ok$'),
        (b"printf 'LAB_FINAL_NET='; for i in /sys/class/net/*; do printf '%s ' \"${i##*/}\"; done; echo\n", r'^LAB_FINAL_NET=lo *$'),
        (b"printf 'LAB_SENTINEL='; cat /tmp/xkeenwrt-test-sentinel\n", r'^LAB_SENTINEL=test-sentinel-v1$'),
    ):
        if not re.search(pattern, command(line), re.M):
            raise RuntimeError('guardian-crash: проверка целостности не прошла')
    print('PASS: guardian-crash-detached и восстановление', flush=True)
    for fault in ('guardian-crash-detached', 'guardian-crash-after-exec'):
        crash = ('XKEENWRT_VALIDATOR_LAB_FAULT=' + fault + ' /usr/libexec/xkeenwrt/xkeenwrt-validate '
                 '< /usr/libexec/xkeenwrt-integration/requests/valid.json; printf "LAB_CRASH_EXIT=%s\\n" "$?"\n').encode()
        result = command(crash)
        if not re.search(r'^LAB_CRASH_EXIT=117$', result, re.M):
            raise RuntimeError(fault + ': авария guardian не подтверждена')
        check = (b"printf 'LAB_STALE='; [ -d /tmp/xkeenwrt-validation/job ] && [ -d /sys/fs/cgroup/xkeenwrt-validation/job ] "
                 b"&& echo yes || echo no\n")
        if not re.search(r'^LAB_STALE=yes$', command(check), re.M):
            raise RuntimeError(fault + ': оставленное задание отсутствует')
        if fault == 'guardian-crash-detached':
            if not re.search(r'^populated 1$', command(b'cat /sys/fs/cgroup/xkeenwrt-validation/job/cgroup.events\n'), re.M):
                raise RuntimeError(fault + ': живой потомок не подтверждён')
        result = command(b"/usr/libexec/xkeenwrt/xkeenwrt-validate --cleanup; printf 'LAB_CLEANUP_EXIT=%s\\n' \"$?\"\n")
        if not re.search(r'^\{"status":"clean","code":"CLEANUP_COMPLETE"\}$', result, re.M) or not re.search(r'^LAB_CLEANUP_EXIT=0$', result, re.M):
            raise RuntimeError(fault + ': --cleanup не подтвердил успех')
        result = command(b"printf 'LAB_RECOVER_CLEAN='; [ ! -e /tmp/xkeenwrt-validation/job ] && [ ! -e /sys/fs/cgroup/xkeenwrt-validation/job ] && echo ok || echo failed\n")
        if not re.search(r'^LAB_RECOVER_CLEAN=ok$', result, re.M):
            raise RuntimeError(fault + ': job остался после --cleanup')
        for line, pattern in (
            (b"printf 'LAB_FINAL_PID1=%s\\n' \"$(cat /proc/1/comm)\"\n", r'^LAB_FINAL_PID1=procd$'),
            (b"printf 'LAB_FINAL_UBUS='; ubus call system board >/dev/null && echo ok || echo failed\n", r'^LAB_FINAL_UBUS=ok$'),
            (b"printf 'LAB_FINAL_NET='; for i in /sys/class/net/*; do printf '%s ' \"${i##*/}\"; done; echo\n", r'^LAB_FINAL_NET=lo *$'),
            (b"printf 'LAB_SENTINEL='; cat /tmp/xkeenwrt-test-sentinel\n", r'^LAB_SENTINEL=test-sentinel-v1$'),
        ):
            if not re.search(pattern, command(line), re.M):
                raise RuntimeError(fault + ': проверка целостности не прошла')
        print('PASS: ' + fault + ' и --cleanup', flush=True)
    os.write(master, b'poweroff -f\n')
    try:
        p.wait(timeout=20)
    except subprocess.TimeoutExpired:
        raise RuntimeError('poweroff не завершился')
    if p.returncode:
        raise RuntimeError(f'ошибка runner: {p.returncode}')
    print('PASS: guardian, очистка, целостность гостя и poweroff')
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
