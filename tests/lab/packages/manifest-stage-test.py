#!/usr/bin/env python3
"""Check both package staging manifests against the files they describe."""
import hashlib
import json
import sys
from pathlib import Path

if len(sys.argv) != 2:
    sys.exit('usage: manifest-stage-test.py STAGE_DIRECTORY')
root = Path(sys.argv[1])
ui = (root / 'ui/usr/share/xkeenwrt/ui-manifest.json').read_bytes()
core = (root / 'core/usr/share/xkeenwrt/core-manifest.json').read_bytes()
if ui != core:
    sys.exit('FAIL: package manifests differ')
manifest = json.loads(ui)
paths = {
    'ui': 'ui/usr/bin/xkeenwrt-ui',
    'core': 'core/usr/libexec/xkeenwrt/mihomo',
    'validator': 'core/usr/libexec/xkeenwrt/xkeenwrt-validate',
    'recovery': 'core/usr/libexec/xkeenwrt/xkeenwrt-recovery',
    'init_ui': 'ui/usr/libexec/xkeenwrt/init/xkeenwrt-ui',
    'init_runtime': 'ui/usr/libexec/xkeenwrt/init/xkeenwrt-runtime',
    'init_core': 'core/usr/libexec/xkeenwrt/init/xkeenwrt-core',
    'init_recovery': 'core/usr/libexec/xkeenwrt/init/xkeenwrt-recovery',
}
if manifest.get('version') != 1 or set(manifest['sha256']) != set(paths):
    sys.exit('FAIL: unsupported manifest schema')
for key, path in paths.items():
    if hashlib.sha256((root / path).read_bytes()).hexdigest() != manifest['sha256'][key]:
        sys.exit(f'FAIL: {key} does not match staged payload')
print('PASS: matching manifests identify all staged component bytes')
