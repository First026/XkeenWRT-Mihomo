#!/usr/bin/env python3
"""Persist bounded serial before forwarding; exits before runner removes VM."""
import os
import sys

if len(sys.argv) != 2:
    sys.exit(2)
limit = 2 * 1024 * 1024
with open(sys.argv[1], 'xb', buffering=0) as log:
    total = 0
    while True:
        data = os.read(0, 4096)
        if not data:
            break
        total += len(data)
        if total > limit:
            sys.exit('serial output exceeded 2 MiB')
        log.write(data)
        remaining = memoryview(data)
        while remaining:
            remaining = remaining[os.write(1, remaining):]
    os.fsync(log.fileno())
