#!/usr/bin/env python3
"""Фиксированная проверка наличия средств топологии в одноразовой VM."""
import os
import pty
import re
import selectors
import signal
import subprocess
import sys
import time
from pathlib import Path

if sys.argv[1:] not in ([], ['--arm64']):
    sys.exit('usage: capabilities.py [--arm64]')
arm = bool(sys.argv[1:])
runner = Path(__file__).resolve().parents[1] / 'openwrt-vm' / 'run.sh'
master, slave = pty.openpty()
p = subprocess.Popen([str(runner)] + (['--arm64-baseline'] if arm else []),
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

commands = (
    b"printf 'LAB_IDENT=%s|%s|%s\\n' \"$(uname -m)\" \"$(uname -r)\" \"$(. /etc/openwrt_release; echo $DISTRIB_TARGET)\"\n",
    b"printf 'LAB_TOOLS='; for x in ip nft fw4 unshare nsenter apk tcpdump nc; do command -v $x >/dev/null && printf '%s ' $x; done; echo\n",
    b"printf 'LAB_MODULES='; for i in /lib/modules/*/*; do [ -e \"$i\" ] && printf '%s ' \"${i##*/}\"; done; echo\n",
    b"printf 'LAB_KMOD='; for i in veth nf_tables nft_tproxy nft_socket nf_tproxy_ipv4 nf_tproxy_ipv6 nf_socket_ipv4 nf_socket_ipv6; do [ -d /sys/module/$i ] && printf '%s ' $i; done; echo\n",
    b"printf 'LAB_BUILTIN='; grep -E '(^|/)(veth|nft_tproxy|nft_socket|nf_tproxy|nf_socket)' /lib/modules/*/modules.builtin 2>/dev/null | tr '\\n' ' '; echo\n",
    b"printf 'LAB_IP='; ip -V 2>&1 | tr '\\n' ' '; echo\n",
    b"printf 'LAB_VETH='; if ip link add xklab0 type veth peer name xklab1 >/dev/null 2>&1; then ip link del xklab0 && echo available || echo cleanup-failed; else echo unavailable; fi\n",
    b"printf 'LAB_TPROXY='; printf 'table inet xkprobe { chain pre { type filter hook prerouting priority mangle; meta l4proto tcp tproxy to :12345; } }\\n' | nft -c -f - >/dev/null 2>&1 && echo available || echo unavailable\n",
    b"printf 'LAB_PACKAGES='; apk info 2>/dev/null | tr '\\n' ' '; echo\n",
    b"printf 'LAB_RECOVERY='; for x in jsonfilter flock lock sync timeout ubus; do command -v $x >/dev/null && printf '%s ' $x; done; [ -r /usr/share/libubox/jshn.sh ] && printf 'jshn.sh '; echo\n",
    b"printf 'LAB_SYNC_HELP='; sync --help 2>&1 | tr '\\n' ' '; echo\n",
    b"printf 'LAB_REPOS='; cat /etc/apk/repositories.d/distfeeds.list 2>/dev/null | tr '\\n' ' '; echo\n",
    b"printf 'LAB_HTTP_TOOLS='; for x in curl wget uclient-fetch nc; do command -v $x 2>/dev/null | tr '\\n' ' '; done; echo\n",
    b"printf 'LAB_WGET_HELP='; wget --help 2>&1 | tr '\\n' ' '; echo\n",
    b"printf 'LAB_NCHELP='; nc -h 2>&1 | tr '\\n' ' '; echo\n",
    b"printf 'LAB_UBUS_PATH='; command -v ubus\n",
    b"printf 'LAB_SERVICE='; ubus call service list '{\"name\":\"xkeenwrt-core\"}' | tr '\\n' ' '; echo\n",
    b"printf 'LAB_LOOPBACK='; ip link show lo | tr '\\n' ' '; echo\n",
    b"printf 'LAB_LOOPADDR='; ip addr show lo | tr '\\n' ' '; echo\n",
    b"printf 'LAB_CGROUP='; cat /sys/fs/cgroup/cgroup.controllers\n",
    b"printf 'LAB_PROCD='; cat /proc/1/comm; printf 'LAB_NET='; for i in /sys/class/net/*; do printf '%s ' \"${i##*/}\"; done; echo\n",
)
error = None
try:
    read_until(rb'Please press Enter to activate this console\.', 90)
    os.write(master, b'\n')
    read_until(rb'root@[^\n]*# ')
    for line in commands:
        result = command(line)
        for item in result.splitlines():
            if item.startswith('LAB_'):
                print(item)
            if item == 'LAB_VETH=cleanup-failed':
                raise RuntimeError('не удалось удалить синтетический veth')
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
