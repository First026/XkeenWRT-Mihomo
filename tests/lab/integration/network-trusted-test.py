#!/usr/bin/env python3
"""Trust and install only signed-index dependencies inside disposable VM."""
import os
import pty
import re
import selectors
import signal
import subprocess
import sys
import time
from pathlib import Path

if len(sys.argv) != 2 or not sys.argv[1].startswith('/tmp/') or Path(sys.argv[1]).exists():
    sys.exit('usage: network-trusted-test.py /tmp/NEW-SERIAL-LOG')
runner = Path(__file__).resolve().with_name('run-network-trusted.sh')
master, slave = pty.openpty()
env = os.environ.copy()
env['XK_SERIAL_LOG'] = sys.argv[1]
p = subprocess.Popen([str(runner)], stdin=slave, stdout=slave, stderr=slave,
                     close_fds=True, start_new_session=True, env=env)
os.close(slave)
sel = selectors.DefaultSelector()
sel.register(master, selectors.EVENT_READ)
start = time.monotonic()
output = bytearray()

def until(pattern, limit=45):
    segment = bytearray()
    deadline = min(start + 165, time.monotonic() + limit)
    while not re.search(pattern, segment.replace(b'\r', b''), re.M):
        if time.monotonic() > deadline:
            raise TimeoutError('истёк срок ожидания VM')
        for key, _ in sel.select(0.2):
            try: chunk = os.read(key.fd, 4096)
            except OSError: chunk = b''
            output.extend(chunk); segment.extend(chunk)
            if len(output) > 2 * 1024 * 1024: raise RuntimeError('превышен лимит serial')
        if p.poll() is not None: raise RuntimeError('VM завершилась до ожидаемого вывода')
    return segment.decode('utf-8', 'replace').replace('\r', '')

def command(line):
    for pos in range(0, len(line), 64):
        os.write(master, line[pos:pos+64]); time.sleep(0.05)
    return until(rb'root@[^\n]*# ', 75)

checks = (
    (b"printf 'NET_IDENT=%s|%s|%s\\n' \"$(uname -m)\" \"$(uname -r)\" \"$(. /etc/openwrt_release; echo $DISTRIB_TARGET)\"\n", 'NET_IDENT=x86_64|6.12.112|x86/64'),
    (b"apk info -v | grep -Fxq 'kernel-6.12.112~b4125196ecec75391093e1e2edeba490-r1' && echo NET_ABI=PASS || echo NET_ABI=FAIL\n", 'NET_ABI=PASS'),
    (b"sha256sum /etc/apk/keys/openwrt-25.12.pem | cut -d ' ' -f 1 | sed 's/^/NET_KEY_SHA=/'\n", 'NET_KEY_SHA=27d61d827d64ccf2f46dce5f52aec6279404d4a00686dafb22f52f3b4ee675f8'),
    (b"cd /usr/share/xkeenwrt-network-lab\n", None),
    (b"sha256sum indexes/x86-base.adb | cut -d ' ' -f 1 | sed 's/^/NET_BASE_SHA=/'\n", 'NET_BASE_SHA=e2a667e4f23ca135864831fa352c3c1c353c292bb6c7716d63a2bb212ad51627'),
    (b"sha256sum indexes/x86-core.adb | cut -d ' ' -f 1 | sed 's/^/NET_CORE_SHA=/'\n", 'NET_CORE_SHA=e02db5e65f73e48359cc4fc75e8995d021ab392548d978d2cea8ed89c33c395c'),
    (b"sha256sum indexes/x86-kmods.adb | cut -d ' ' -f 1 | sed 's/^/NET_KMOD_SHA=/'\n", 'NET_KMOD_SHA=ce8105f6fe7a6070c5964fd02174d637606ccf96d6d8f42078e6efe726a0c6cb'),
    (b"cd /usr/share/xkeenwrt-network-lab; for n in base core kmods; do apk verify indexes/x86-$n.adb >/dev/null 2>&1 || break; done; [ \"$n\" = kmods ] && apk verify indexes/x86-kmods.adb >/dev/null 2>&1 && echo NET_SIGNATURE=PASS || echo NET_SIGNATURE=FAIL\n", 'NET_SIGNATURE=PASS'),
    (b"mkdir -p /tmp/xk-repos/base /tmp/xk-repos/core /tmp/xk-repos/kmods\n", None),
    (b"for n in base core kmods; do cp indexes/x86-$n.adb /tmp/xk-repos/$n/packages.adb; cp ./*.apk /tmp/xk-repos/$n/; done; echo NET_REPO=PASS\n", 'NET_REPO=PASS'),
    (b"echo file:///tmp/xk-repos/base/packages.adb > /tmp/xk-repos.list\n", None),
    (b"echo file:///tmp/xk-repos/core/packages.adb >> /tmp/xk-repos.list\n", None),
    (b"echo file:///tmp/xk-repos/kmods/packages.adb >> /tmp/xk-repos.list\n", None),
    (b"apk --no-network --repositories-file /tmp/xk-repos.list add ip-full kmod-veth kmod-nft-tproxy kmod-nft-socket >/tmp/xk-apk.log 2>&1 && echo NET_INSTALL=PASS || { echo NET_INSTALL=FAIL; cat /tmp/xk-apk.log; }\n", 'NET_INSTALL=PASS'),
    (b"modprobe veth && modprobe nft_tproxy && modprobe nft_socket && echo NET_MODULES=PASS || echo NET_MODULES=FAIL\n", 'NET_MODULES=PASS'),
    (b"ip link add xkeen-probe0 type veth peer name xkeen-probe1 && ip link del xkeen-probe0 && echo NET_VETH=PASS || echo NET_VETH=FAIL\n", 'NET_VETH=PASS'),
    (b"printf '%s\\n' 'table inet xkeenwrt_probe { chain test { type filter hook prerouting priority mangle; tcp dport 12345 tproxy to :12345 accept; } }' > /tmp/xk-probe.nft\n", None),
    (b"nft -c -f /tmp/xk-probe.nft >/tmp/xk-nft.out 2>/tmp/xk-nft.err && echo NET_NFT=PASS || echo NET_NFT=FAIL\n", 'NET_NFT=PASS'),
    (b"[ \"$(ls /sys/class/net)\" = lo ] && [ \"$(cat /proc/1/comm)\" = procd ] && ubus call system board >/dev/null && echo NET_BASELINE=PASS || echo NET_BASELINE=FAIL\n", 'NET_BASELINE=PASS'),
)
error = None
try:
    until(rb'Please press Enter to activate this console\.', 90)
    os.write(master, b'\n'); until(rb'root@[^\n]*# ')
    for line, expected in checks:
        result = command(line)
        for item in result.splitlines():
            if re.fullmatch(r'NET_[A-Z_]+=[A-Za-z0-9|/.-]+', item): print(item, flush=True)
        if expected == 'NET_NFT=PASS' and expected not in result.splitlines():
            detail = command(b"head -c 2048 /tmp/xk-nft.err; echo\n")
            print('NET_NFT_ORIGINAL_DIAGNOSTIC=' + detail, flush=True)
            if 'syntax error' not in detail.lower():
                print(command(b"[ \"$(ls /sys/class/net)\" = lo ] && echo NET_BASELINE=PASS || echo NET_BASELINE=FAIL\n"), flush=True)
                raise RuntimeError('nft -c не прошёл, ошибка не классифицирована как syntax')
            for repair in (
                b"echo 'table inet xkeenwrt_probe {' > /tmp/xk-probe-multiline.nft\n",
                b"echo ' chain test {' >> /tmp/xk-probe-multiline.nft\n",
                b"echo '  type filter hook prerouting priority mangle;' >> /tmp/xk-probe-multiline.nft\n",
                b"echo '  tcp dport 12345 tproxy to :12345 accept' >> /tmp/xk-probe-multiline.nft\n",
                b"echo ' }' >> /tmp/xk-probe-multiline.nft\n",
                b"echo '}' >> /tmp/xk-probe-multiline.nft\n",
            ):
                command(repair)
            fixed = command(b"nft -c -f /tmp/xk-probe-multiline.nft >/tmp/xk-nft2.out 2>/tmp/xk-nft2.err && echo NET_NFT_MULTILINE=PASS || echo NET_NFT_MULTILINE=FAIL\n")
            print(fixed, flush=True)
            if 'NET_NFT_MULTILINE=PASS' not in fixed.splitlines():
                print(command(b"head -c 2048 /tmp/xk-nft2.err; echo\n"), flush=True)
                raise RuntimeError('многострочный nft -c не прошёл')
            continue
        if expected and expected not in result.splitlines():
            print(result[-4000:], flush=True)
            raise RuntimeError(f'не прошёл {expected}')
    os.write(master, b'poweroff -f\n'); p.wait(timeout=20)
    if p.returncode: raise RuntimeError(f'runner exit {p.returncode}')
except (OSError, TimeoutError, RuntimeError) as exc:
    error = str(exc)
finally:
    if p.poll() is None:
        p.send_signal(signal.SIGTERM)
        try: p.wait(timeout=55)
        except subprocess.TimeoutExpired:
            os.killpg(p.pid, signal.SIGKILL); p.wait(); error = (error or 'runner') + '; очистка не подтверждена'
    sel.close(); os.close(master)
log = Path(sys.argv[1])
if not log.exists(): sys.exit('FAIL: serial log не создан')
print(f'SERIAL_LOG={log} BYTES={log.stat().st_size}', flush=True)
if error: sys.exit('FAIL: ' + error)
print('PASS: trusted signed repositories, offline install and module probes')
