#!/usr/bin/env python3
"""Assert fixed differential outcomes from a saved bounded VM serial log."""
import sys
from pathlib import Path

if len(sys.argv) != 2:
    sys.exit('usage: validator-diff-assert.py SERIAL_LOG')
data = Path(sys.argv[1]).read_bytes()
if len(data) > 2 * 1024 * 1024:
    sys.exit('FAIL: serial log exceeds bound')
lines = data.replace(b'\r', b'').splitlines()
required = (
    b'DIAG_REQUEST=VERIFIED',
    b'DIAG_VALIDATOR_PIN=OK',
    b'DIAG_DIRECT_CLEANUP_EXIT=ZERO',
    b'DIAG_DIRECT_CLEANUP_RESULT=CLEANUP_COMPLETE',
    b'DIAG_DIRECT_PROTOCOL_EXIT=ZERO',
    b'DIAG_DIRECT_PROTOCOL_RESULT=VALID',
    b'DIAG_FD_IDENTITY=OK',
    b'DIAG_FD_CGROUP=OK',
    b'DIAG_FD_PIN=OK',
    b'DIAG_FD_CLEANUP_LAUNCH=ZERO',
    b'DIAG_FD_CLEANUP_RESULT=CLEANUP_COMPLETE',
    b'DIAG_FD_PROTOCOL_LAUNCH=ZERO',
    b'DIAG_FD_PROTOCOL_RESULT=VALID',
    b'DIAG_FD_WORKER=ZERO',
    b'DIAG_PROBE_EXIT=0',
    b'DIAG_DONE=YES',
)
missing = [v.decode() for v in required if lines.count(v) != 1]
if missing:
    sys.exit('FAIL: missing or duplicated outcomes: ' + ', '.join(missing))
print('PASS: direct and frozen FD launcher both validated the same request')
