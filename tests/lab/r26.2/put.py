#!/usr/bin/env python3
"""Upload one local text file into the lab guest over its serial console.

Usage: put.py SOCKET LOCAL_FILE REMOTE_PATH

The guest busybox has no base64, so the file goes as a quoted heredoc in short
paced chunks (the emulated UART drops input that arrives faster than the guest
reads it). It is written to a temporary file and moved into place only when its
SHA-256 matches; a failed upload never truncates the target.
"""
import hashlib
import socket
import sys
import time
import uuid

sock_path, local, remote = sys.argv[1:4]
data = open(local, "rb").read()
text = data.decode()
assert "\r" not in text, "text files only"
digest = hashlib.sha256(data).hexdigest()
marker = "XKPUT" + uuid.uuid4().hex[:12]
tmp = f"/tmp/{marker}.part"
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(sock_path)
s.settimeout(0.02)


def drain():
    out = b""
    while True:
        try:
            chunk = s.recv(65536)
            if not chunk:
                return out
            out += chunk
        except socket.timeout:
            return out


seen = b""


def send(line):
    global seen
    raw = line.encode()
    for i in range(0, len(raw), 32):
        s.sendall(raw[i:i + 32])
        time.sleep(0.02)
        seen += drain()


send("\n")
send(f"stty -echo 2>/dev/null; cat > {tmp} <<'{marker}'\n")
body = text if text.endswith("\n") else text + "\n"
for row in body.splitlines(keepends=True):
    send(row)
send(f"{marker}\n")
send(f"if [ \"$(sha256sum {tmp} | cut -c1-64)\" = {digest} ]; then mv {tmp} {remote} && chmod 755 {remote} "
     f"&& echo {marker}=OK; else rm -f {tmp}; echo {marker}=BAD; fi; stty echo 2>/dev/null\n")
end = time.time() + 120
while time.time() < end:
    seen += drain()
    out = seen.decode(errors="replace")
    if f"{marker}=OK" in out:
        print("OK")
        sys.exit(0)
    if f"{marker}=BAD" in out:
        print("BAD: checksum mismatch, target unchanged")
        sys.exit(1)
    time.sleep(0.2)
print("TIMEOUT")
sys.exit(1)
