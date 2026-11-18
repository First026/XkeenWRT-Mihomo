#!/usr/bin/env python3
"""Exercise the target preview process through its loopback HTTP API."""
import http.client
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import time

assert os.getuid() != 0
state = pathlib.Path(tempfile.mkdtemp(prefix="xkeenwrt-arm64-")) / "state"
proc = subprocess.Popen(["/lab/qemu-aarch64-static", "/lab/xkeenwrt-ui", "preview", "--state-dir", str(state), "--port", "18080"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def request(method, path, payload=None, cookie=None):
    conn = http.client.HTTPConnection("127.0.0.1", 18080, timeout=20)
    headers = {"Host": "127.0.0.1:18080"}
    if payload is not None:
        headers["Content-Type"] = "application/json"
    if cookie:
        headers["Cookie"] = cookie
    conn.request(method, path, None if payload is None else json.dumps(payload), headers)
    response = conn.getresponse()
    body = response.read()
    result = (response.status, json.loads(body), response.getheader("Set-Cookie"))
    conn.close()
    return result

try:
    for _ in range(200):
        if proc.poll() is not None:
            raise RuntimeError(f"preview exited early: {proc.returncode}")
        try:
            status, _, _ = request("GET", "/api/auth/login")
            if status == 200:
                break
        except (OSError, http.client.HTTPException):
            time.sleep(0.1)
    else:
        raise RuntimeError("preview did not become ready")
    if sys.argv[1:] == ["negative"]:
        print("Intentional failure after ARM64 preview startup", flush=True)
        sys.exit(73)
    assert sys.argv[1:] == ["normal"]
    assert request("GET", "/api/profiles")[0] == 401
    token = (state / "bootstrap-token").read_text().strip()
    status, result, cookie = request("POST", "/api/auth/setup", {"token": token, "password": "synthetic-smoke-password"})
    assert status == 200 and result["success"] and cookie
    cookie = cookie.split(";", 1)[0]
    assert not (state / "bootstrap-token").exists()
    source = "mixed-port: 9999\nbind-address: 0.0.0.0\nexternal-controller: 0.0.0.0:9090\nproxies: []\n"
    status, result, _ = request("PUT", "/api/profiles/smoke", {"source": source, "expected_revision": None}, cookie)
    assert status == 200 and result["profile"]["source"] == source
    revision = result["profile"]["revision"]
    status, result, _ = request("GET", "/api/profiles/smoke", cookie=cookie)
    assert status == 200 and result["profile"]["source"] == source and result["profile"]["revision"] == revision
    status, result, _ = request("POST", "/api/profiles/smoke/prepare", {"expected_revision": revision}, cookie)
    assert status == 200 and result["success"]
    preview = result["preparation"]
    assert preview["source"] == source and preview["revision"] == revision
    assert preview["mode"] == "manual-preview" and preview["core_validation"] == "not_run" and preview["activatable"] is False
    effective = preview["effective_yaml"]
    assert re.search(r'(?m)^\s*["\']?mixed-port["\']?:[ \t]*7890[ \t]*,?[ \t]*$', effective)
    assert re.search(r'(?m)^\s*["\']?bind-address["\']?:[ \t]*["\']?127\.0\.0\.1["\']?[ \t]*,?[ \t]*$', effective)
    assert re.search(r'(?m)^\s*["\']?external-controller["\']?:[ \t]*(?:""|\'\'|null)?[ \t]*,?[ \t]*$', effective)
    status, result, _ = request("POST", "/api/profiles/smoke/prepare", {"expected_revision": "stale-revision"}, cookie)
    assert status == 409 and result["code"] == "CONFLICT"
    status, result, _ = request("GET", "/api/profiles/smoke", cookie=cookie)
    assert status == 200 and result["profile"]["source"] == source and result["profile"]["revision"] == revision
    assert request("POST", "/api/auth/logout", {}, cookie)[0] == 200
    assert request("GET", "/api/profiles/smoke", cookie=cookie)[0] == 401
    status, result, cookie = request("POST", "/api/auth/login", {"password": "synthetic-smoke-password"})
    assert status == 200 and result["success"] and cookie
    assert request("GET", "/api/profiles/smoke", cookie=cookie.split(";", 1)[0])[1]["profile"]["source"] == source
    print("PASS: ARM64 preview authentication, profile save, preparation and stale revision")
finally:
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
