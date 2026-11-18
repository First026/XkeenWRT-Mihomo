#!/bin/sh
# Build unsigned, inert APKv3 packages from explicitly identified static artifacts.
set -eu
# A user namespace gives package metadata root ownership without host privileges.
if [ "$(id -u)" -ne 0 ]; then exec unshare -Ur "$0" "$@"; fi
: "${XK_APK_MKPKG:?}" "${XK_BACKEND:?}" "${XK_BACKEND_SHA256:?}" "${XK_VALIDATOR:?}" "${XK_VALIDATOR_SHA256:?}" "${XK_RECOVERY:?}" "${XK_RECOVERY_SHA256:?}" "${XK_SOURCE_ARCHIVE:?}" "${XK_RECIPE_ARCHIVE:?}" "${XK_BUILD_ID:?}" "${XK_ARCH:?}" "${XK_VERSION:?}" "${XK_OUTPUT:?}" "${XK_MIHOMO_LICENSE:?}"
case "$XK_VERSION" in *[!a-zA-Z0-9.+_-]*|'') echo 'bad version' >&2; exit 1;; esac
[ "${#XK_VERSION}" -le 128 ] || { echo 'version too long' >&2; exit 1; }
case "$XK_ARCH" in
  aarch64_cortex-a53) machine=AArch64; archive=/workspace/.cache/xkeenwrt/mihomo-linux-arm64-v1.19.34.gz; digest=daaf78a6240a282cdfd75bcbf98fe321f6bd52765cc29e79f344191198f0b50f ;;
  *) echo 'unsupported architecture' >&2; exit 1;;
esac
repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
verify() { printf '%s  %s\n' "$1" "$2" | sha256sum -c -; }
mkdir -p "$XK_OUTPUT"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
ui="$tmp/ui"; core="$tmp/core"
init_dir=${XK_INIT_DIR:-"$repo/openwrt/xkeenwrt-ui/files/etc/init.d"}
mkdir "$tmp/init"
for s in xkeenwrt-ui xkeenwrt-runtime xkeenwrt-core xkeenwrt-recovery; do
  install -m 755 "$init_dir/$s" "$tmp/init/$s"
done
# Stage exactly the bytes that will be verified, identified and packed.
cp "$XK_BACKEND" "$tmp/backend"
cp "$XK_VALIDATOR" "$tmp/validator"
cp "$XK_RECOVERY" "$tmp/recovery"
cp "$XK_SOURCE_ARCHIVE" "$tmp/source"
cp "$XK_RECIPE_ARCHIVE" "$tmp/recipe"
cp "$archive" "$tmp/mihomo.gz"
cp "$repo/scripts/package-hook.sh" "$tmp/package-hook"
verify "$XK_BACKEND_SHA256" "$tmp/backend"
verify "$XK_VALIDATOR_SHA256" "$tmp/validator"
verify "$XK_RECOVERY_SHA256" "$tmp/recovery"
verify "$digest" "$tmp/mihomo.gz"
verify 3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986 "$XK_MIHOMO_LICENSE"
computed_id=$(XK_SOURCE_ARCHIVE="$tmp/source" XK_RECIPE_ARCHIVE="$tmp/recipe" XK_VALIDATOR="$tmp/validator" XK_RECOVERY="$tmp/recovery" XK_INIT_DIR="$tmp/init" XK_HOOK_FILE="$tmp/package-hook" XK_MIHOMO_ARCHIVE="$tmp/mihomo.gz" "$repo/scripts/package-build-id.sh")
[ "$XK_BUILD_ID" = "$computed_id" ] || { echo 'build identity does not match staged inputs' >&2; exit 1; }
for binary in "$tmp/backend" "$tmp/validator" "$tmp/recovery"; do
  readelf -h "$binary" | grep -F "Machine:" | grep -F "$machine" >/dev/null || { echo 'wrong ELF machine' >&2; exit 1; }
  if readelf -l "$binary" | grep -q INTERP || readelf -d "$binary" 2>/dev/null | grep -q NEEDED; then echo 'ELF is not static' >&2; exit 1; fi
done
sha256sum "$tmp/init/"*
for root in "$ui" "$core"; do
  mkdir -p "$root/usr/libexec/xkeenwrt/init" "$root/usr/share/licenses" "$root/lib/apk/packages"
done
mkdir -p "$ui/usr/bin"
install -m 755 "$tmp/backend" "$ui/usr/bin/xkeenwrt-ui"
install -m 755 "$tmp/validator" "$core/usr/libexec/xkeenwrt/xkeenwrt-validate"
install -m 755 "$tmp/recovery" "$core/usr/libexec/xkeenwrt/xkeenwrt-recovery"
gzip -dc "$tmp/mihomo.gz" > "$tmp/mihomo"
readelf -h "$tmp/mihomo" | grep -F "$machine" >/dev/null
if readelf -l "$tmp/mihomo" | grep -q INTERP || readelf -d "$tmp/mihomo" 2>/dev/null | grep -q NEEDED; then echo 'Mihomo ELF is not static' >&2; exit 1; fi
for s in xkeenwrt-ui xkeenwrt-runtime; do install -m 755 "$tmp/init/$s" "$ui/usr/libexec/xkeenwrt/init/$s"; done
for s in xkeenwrt-core xkeenwrt-recovery; do install -m 755 "$tmp/init/$s" "$core/usr/libexec/xkeenwrt/init/$s"; done
install -m 755 "$tmp/package-hook" "$ui/usr/libexec/xkeenwrt/package-hook-ui"
install -m 755 "$tmp/package-hook" "$core/usr/libexec/xkeenwrt/package-hook-core"
mkdir -p "$ui/usr/share/licenses/xkeenwrt-ui" "$core/usr/share/licenses/xkeenwrt-core" "$core/lib/upgrade/keep.d"
install -m 644 "$repo/LICENSE" "$ui/usr/share/licenses/xkeenwrt-ui/LICENSE"
install -m 644 "$XK_MIHOMO_LICENSE" "$core/usr/share/licenses/xkeenwrt-core/LICENSE.mihomo"
install -m 644 "$repo/LICENSE" "$core/usr/share/licenses/xkeenwrt-core/LICENSE.xkeenwrt"
printf '/etc/xkeenwrt/\n' > "$core/lib/upgrade/keep.d/xkeenwrt"
# Identical independent copies make a partial two-package publication fail closed.
# Paths are fixed by the runtime, never supplied by the manifest.
ui_hash=$(sha256sum "$ui/usr/bin/xkeenwrt-ui" | cut -d ' ' -f 1)
core_hash=$(sha256sum "$tmp/mihomo" | cut -d ' ' -f 1)
validator_hash=$(sha256sum "$core/usr/libexec/xkeenwrt/xkeenwrt-validate" | cut -d ' ' -f 1)
recovery_hash=$(sha256sum "$core/usr/libexec/xkeenwrt/xkeenwrt-recovery" | cut -d ' ' -f 1)
init_ui_hash=$(sha256sum "$ui/usr/libexec/xkeenwrt/init/xkeenwrt-ui" | cut -d ' ' -f 1)
init_runtime_hash=$(sha256sum "$ui/usr/libexec/xkeenwrt/init/xkeenwrt-runtime" | cut -d ' ' -f 1)
init_core_hash=$(sha256sum "$core/usr/libexec/xkeenwrt/init/xkeenwrt-core" | cut -d ' ' -f 1)
init_recovery_hash=$(sha256sum "$core/usr/libexec/xkeenwrt/init/xkeenwrt-recovery" | cut -d ' ' -f 1)
mkdir -p "$ui/usr/share/xkeenwrt" "$core/usr/share/xkeenwrt"
printf '{"version":1,"build_id":"%s","package_version":"%s","sha256":{"ui":"%s","core":"%s","validator":"%s","recovery":"%s","init_runtime":"%s","init_ui":"%s","init_core":"%s","init_recovery":"%s"}}\n' \
  "$XK_BUILD_ID" "$XK_VERSION" "$ui_hash" "$core_hash" "$validator_hash" "$recovery_hash" \
  "$init_runtime_hash" "$init_ui_hash" "$init_core_hash" "$init_recovery_hash" > "$ui/usr/share/xkeenwrt/ui-manifest.json"
install -m 644 "$ui/usr/share/xkeenwrt/ui-manifest.json" "$core/usr/share/xkeenwrt/core-manifest.json"
chmod 644 "$ui/usr/share/xkeenwrt/ui-manifest.json"
for part in core ui; do
  root="$tmp/$part"
  (cd "$root" && find . -type f,l -printf '/%P\n' | sort > "lib/apk/packages/xkeenwrt-$part.list")
  find "$root" -type d -exec chmod 755 {} +
  chmod 644 "$root/lib/apk/packages/xkeenwrt-$part.list"
  printf '#!/bin/sh\nexec /usr/libexec/xkeenwrt/package-hook-%s install %s\n' "$part" "$part" > "$tmp/$part-post"
  printf '#!/bin/sh\nexec /usr/libexec/xkeenwrt/package-hook-%s remove %s\n' "$part" "$part" > "$tmp/$part-pre"
  # The old installed hook is the only code available during pre-upgrade. Embed
  # this package's pinned hook so an r12 flat Mihomo binary is adopted before
  # APK removes it; the post-upgrade hook still runs the newly installed copy.
  {
    printf '#!/bin/sh\nset -- upgrade %s\n' "$part"
    sed '1d' "$repo/scripts/package-hook.sh"
  } > "$tmp/$part-upgrade"
  chmod 755 "$tmp/$part-post" "$tmp/$part-pre" "$tmp/$part-upgrade"
  depends='libc procd'
  [ "$part" != ui ] || depends="$depends ca-bundle ip-full kmod-nft-tproxy kmod-nft-socket kmod-nf-conntrack-netlink"
  [ "$part" != ui ] || depends="$depends xkeenwrt-core=$XK_VERSION"
  license=MIT; [ "$part" != core ] || license='MIT AND GPL-3.0-only'
  set -- mkpkg --info "name:xkeenwrt-$part" --info "version:$XK_VERSION" --info "arch:$XK_ARCH" --info "license:$license" --info "depends:$depends" --info 'origin:XkeenWRT' --info 'url:https://github.com/MetaCubeX/mihomo' --script "post-install:$tmp/$part-post" --script "post-upgrade:$tmp/$part-post" --script "pre-upgrade:$tmp/$part-upgrade" --script "pre-deinstall:$tmp/$part-pre" --files "$root" --output "$XK_OUTPUT/xkeenwrt-$part-$XK_VERSION.apk"
  if [ -n "${XK_SIGN_KEY:-}" ]; then set -- "$@" --sign-key "$XK_SIGN_KEY"; fi
  "$XK_APK_MKPKG" "$@"
done
if [ -n "${XK_STAGE_OUTPUT:-}" ]; then
  [ ! -e "$XK_STAGE_OUTPUT" ] || { echo 'stage output already exists' >&2; exit 1; }
  mkdir -p "$XK_STAGE_OUTPUT"
  cp -a "$core" "$XK_STAGE_OUTPUT/core"
  cp -a "$ui" "$XK_STAGE_OUTPUT/ui"
  printf '%s\n' "$XK_ARCH" > "$XK_STAGE_OUTPUT/ARCH"
  printf '%s\n' "$XK_VERSION" > "$XK_STAGE_OUTPUT/VERSION"
  (cd "$XK_STAGE_OUTPUT" && find core ui -type f -print0 | sort -z | xargs -0 sha256sum > MANIFEST.sha256)
fi
sha256sum "$XK_OUTPUT"/*.apk
