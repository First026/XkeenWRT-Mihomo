#!/usr/bin/env python3
"""Run one shell command in the lab guest over its serial console socket.

Usage: console.py SOCKET TIMEOUT_SECONDS COMMAND...
Prints the command output and exits with the guest command's status.
"""
import os
import re
import socket
import sys
import time
import uuid

sock_path, timeout = sys.argv[1], float(sys.argv[2])
command = " ".join(sys.argv[3:])
marker = "XKDONE" + uuid.uuid4().hex[:12]
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(sock_path)
s.settimeout(1.0)


def drain(seconds):
    end = time.time() + seconds
    data = b""
    while time.time() < end:
        try:
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
        except socket.timeout:
            pass
    return data


drain(0.3)
# Activate the console if it is still waiting, then run the command with a marker.
line = f"{command}; echo {marker}:$?\n" if command else f"echo {marker}:$?\n"
def send_slow(data):
    # The emulated UART drops input that arrives faster than the guest reads it.
    for i in range(0, len(data), 32):
        s.sendall(data[i:i + 32])
        time.sleep(0.02)


s.sendall(b"\n")
drain(0.5)
if os.environ.get("XK_PUT"):
    # Upload a local text file through a quoted heredoc: XK_PUT=local, command = remote path.
    text = open(os.environ["XK_PUT"]).read()
    remote = command
    send_slow(f"cat > {remote} <<'XKEOF_END'\n".encode())
    for row in text.splitlines():
        send_slow((row + "\n").encode())
        drain(0.01)
    send_slow(b"XKEOF_END\n")
    line = f"chmod 755 {remote}; wc -l < {remote}; echo {marker}:$?\n"
send_slow(line.encode())
buf = b""
end = time.time() + timeout
pattern = re.compile((marker + r":(\d+)").encode())
while time.time() < end:
    try:
        chunk = s.recv(65536)
    except socket.timeout:
        continue
    if not chunk:
        break
    buf += chunk
    # Skip the echoed command line itself: wait for the marker at a line start.
    found = [m for m in pattern.finditer(buf) if buf[max(0, m.start() - 1):m.start()] in (b"\n", b"\r")]
    if found:
        out = buf[: found[-1].start()].decode(errors="replace")
        first_nl = out.find("\n")
        sys.stdout.write(out[first_nl + 1:] if first_nl >= 0 else out)
        sys.exit(int(found[-1].group(1)))
sys.stdout.write(buf.decode(errors="replace"))
print(f"\n[console.py] timeout after {timeout}s", file=sys.stderr)
sys.exit(124)
