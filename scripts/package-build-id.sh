#!/bin/sh
# Canonical identity, computed before backend compilation from exact build inputs.
set -eu
: "${XK_SOURCE_ARCHIVE:?}" "${XK_RECIPE_ARCHIVE:?}" "${XK_VERSION:?}" "${XK_ARCH:?}" "${XK_VALIDATOR:?}" "${XK_RECOVERY:?}"
case "$XK_VERSION" in *[!a-zA-Z0-9.+_-]*|'') echo 'bad version' >&2; exit 1;; esac
[ "${#XK_VERSION}" -le 128 ] || { echo 'version too long' >&2; exit 1; }
case "$XK_ARCH" in
  aarch64_cortex-a53) archive=/workspace/.cache/xkeenwrt/mihomo-linux-arm64-v1.19.34.gz ;;
  *) echo 'unsupported architecture' >&2; exit 1;;
esac
archive=${XK_MIHOMO_ARCHIVE:-$archive}
repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
init_dir=${XK_INIT_DIR:-"$repo/openwrt/xkeenwrt-ui/files/etc/init.d"}
hash() { result=$(sha256sum "$1") || return 1; printf '%s\n' "${result%% *}"; }
source_hash=$(hash "$XK_SOURCE_ARCHIVE")
recipe_hash=$(hash "$XK_RECIPE_ARCHIVE")
core_hash=$(hash "$archive")
validator_hash=$(hash "$XK_VALIDATOR")
recovery_hash=$(hash "$XK_RECOVERY")
init_ui=$(hash "$init_dir/xkeenwrt-ui")
init_runtime=$(hash "$init_dir/xkeenwrt-runtime")
init_core=$(hash "$init_dir/xkeenwrt-core")
init_recovery=$(hash "$init_dir/xkeenwrt-recovery")
hook_hash=$(hash "${XK_HOOK_FILE:-$repo/scripts/package-hook.sh}")
{
  printf 'xkeenwrt-build-id-v1\nversion=%s\narch=%s\n' "$XK_VERSION" "$XK_ARCH"
  printf 'source=%s\nrecipe=%s\nmihomo=%s\nvalidator=%s\nrecovery=%s\n' "$source_hash" "$recipe_hash" "$core_hash" "$validator_hash" "$recovery_hash"
  printf 'init-xkeenwrt-ui=%s\ninit-xkeenwrt-runtime=%s\ninit-xkeenwrt-core=%s\ninit-xkeenwrt-recovery=%s\n' "$init_ui" "$init_runtime" "$init_core" "$init_recovery"
  printf 'package-hook=%s\n' "$hook_hash"
} | sha256sum | cut -d ' ' -f 1
