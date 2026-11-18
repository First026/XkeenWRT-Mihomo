#!/bin/sh
# A changed component, source snapshot or release must change build identity.
set -eu
repo=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
mkdir "$tmp/init"
for s in xkeenwrt-ui xkeenwrt-runtime xkeenwrt-core xkeenwrt-recovery; do printf 'init-%s\n' "$s" > "$tmp/init/$s"; done
printf 'snapshot\n' > "$tmp/source"
printf 'recipe\n' > "$tmp/recipe"
printf 'validator\n' > "$tmp/validator"
printf 'recovery\n' > "$tmp/recovery"
export XK_SOURCE_ARCHIVE="$tmp/source" XK_RECIPE_ARCHIVE="$tmp/recipe" XK_INIT_DIR="$tmp/init" XK_VALIDATOR="$tmp/validator" XK_RECOVERY="$tmp/recovery" XK_ARCH=x86_64 XK_VERSION=0.1-r1
identity() { "$repo/scripts/package-build-id.sh"; }
original=$(identity)
[ "${#original}" = 64 ] || exit 1
[ "$(identity)" = "$original" ] || exit 1
XK_VERSION=0.1-r2; export XK_VERSION
[ "$(identity)" != "$original" ] || exit 1
XK_VERSION=0.1-r1; export XK_VERSION
printf 'changed\n' >> "$tmp/recovery"
[ "$(identity)" != "$original" ] || exit 1
printf 'recovery\n' > "$tmp/recovery"
printf 'changed\n' >> "$tmp/init/xkeenwrt-core"
[ "$(identity)" != "$original" ] || exit 1
printf 'init-xkeenwrt-core\n' > "$tmp/init/xkeenwrt-core"
printf 'changed\n' >> "$tmp/source"
[ "$(identity)" != "$original" ] || exit 1
printf 'snapshot\n' > "$tmp/source"
printf 'changed\n' >> "$tmp/recipe"
[ "$(identity)" != "$original" ] || exit 1
rm -f "$tmp/validator"
if identity >/dev/null 2>&1; then echo 'FAIL: missing input accepted' >&2; exit 1; fi
echo 'PASS: identity changes with source, recipe, release, helper and init; missing input rejected'
