#!/bin/sh
# Public build seam: refuse missing inputs rather than creating incomplete APKs.
set -eu
repo=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
if "$repo/scripts/package-build.sh" >/dev/null 2>&1; then
    echo 'FAIL: package builder accepted missing inputs' >&2
    exit 1
fi
[ -x "$repo/scripts/package-build.sh" ] || { echo 'FAIL: package builder missing' >&2; exit 1; }
echo 'PASS: missing inputs refused'
