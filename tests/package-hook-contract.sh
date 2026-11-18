#!/bin/sh
set -eu
repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
root="$tmp/root"
bin="$tmp/bin"
state="$tmp/state"
real_timeout=$(command -v timeout)
mkdir -p "$root/etc/init.d" "$root/etc/rc.d" "$root/usr/libexec/xkeenwrt/init" "$bin" "$state"
sed "s|/etc|$root/etc|g; s|/usr/libexec|$root/usr/libexec|g" "$repo/scripts/package-hook.sh" > "$tmp/package-hook"
chmod 755 "$tmp/package-hook"

cat > "$bin/ubus" <<'EOF'
#!/bin/sh
if [ "${XK_HANG_UBUS:-0}" = 1 ]; then while :; do sleep 1; done; fi
request=$4
name=${request#*\"name\":\"}
name=${name%%\"*}
state_file="$XK_TEST_STATE/$name"
status=false
[ ! -f "$state_file" ] || status=$(cat "$state_file")
printf '{"%s":{"instances":{"main":{"running":%s}}}}\n' "$name" "$status"
EOF
cat > "$bin/timeout" <<EOF
#!/bin/sh
[ "\$1" = -k ] && [ "\$2" = 1 ] || exit 2
shift 2
[ "\$1" = 1 ] || [ "\$1" = 3 ] || exit 2
shift
exec "$real_timeout" -k 1 0.05 "\$@"
EOF
cat > "$bin/jsonfilter" <<'EOF'
#!/bin/sh
expression=$2
case "$expression" in
  *".instances.*.running") sed -n 's/.*"running":[[:space:]]*\(true\|false\).*/\1/p' ;;
  *) cat ;;
esac
EOF
chmod 755 "$bin/ubus" "$bin/jsonfilter"
chmod 755 "$bin/timeout"

make_service() {
  service=$1
  script="$root/usr/libexec/xkeenwrt/init/$service"
  cat > "$script" <<EOF
#!/bin/sh
[ "\${1:-}" = stop ] || exit 2
printf false > "$state/$service"
EOF
  chmod 755 "$script"
  ln -s "$root/usr/libexec/xkeenwrt/init/$service" "$root/etc/init.d/$service"
  ln -s "../init.d/$service" "$root/etc/rc.d/S90$service"
}

make_service xkeenwrt-ui
make_service xkeenwrt-runtime
printf true > "$state/xkeenwrt-ui"
printf true > "$state/xkeenwrt-runtime"
env -u IPKG_INSTROOT PATH="$bin:$PATH" XK_TEST_STATE="$state" "$tmp/package-hook" remove ui
[ "$(cat "$state/xkeenwrt-ui")" = false ]
[ "$(cat "$state/xkeenwrt-runtime")" = false ]
[ ! -e "$root/etc/init.d/xkeenwrt-ui" ]
[ ! -e "$root/etc/init.d/xkeenwrt-runtime" ]

# Without a rescue or the immutable never-enabled proof, the hook must leave
# core/recovery alive and retain their service links for a later reinstall.
make_service xkeenwrt-core
make_service xkeenwrt-recovery
printf true > "$state/xkeenwrt-core"
printf true > "$state/xkeenwrt-recovery"
env -u IPKG_INSTROOT PATH="$bin:$PATH" XK_TEST_STATE="$state" "$tmp/package-hook" remove core
[ "$(cat "$state/xkeenwrt-core")" = true ]
[ "$(cat "$state/xkeenwrt-recovery")" = true ]
[ -L "$root/etc/init.d/xkeenwrt-core" ]
[ -L "$root/etc/init.d/xkeenwrt-recovery" ]

# A hung init stop and a hung ubus response are both cut off by the fixed
# command budget; inability to verify shutdown keeps the owned link in place.
make_service xkeenwrt-ui
cat > "$root/usr/libexec/xkeenwrt/init/xkeenwrt-ui" <<'EOF'
#!/bin/sh
while :; do sleep 1; done
EOF
chmod 755 "$root/usr/libexec/xkeenwrt/init/xkeenwrt-ui"
printf true > "$state/xkeenwrt-ui"
env -u IPKG_INSTROOT PATH="$bin:$PATH" XK_TEST_STATE="$state" XK_HANG_STOP=1 XK_HANG_UBUS=1 "$tmp/package-hook" remove ui
[ -L "$root/etc/init.d/xkeenwrt-ui" ]

# Foreign links never enter the fixed-stop path and remain untouched.
rm "$root/etc/init.d/xkeenwrt-ui"
ln -s "$root/usr/libexec/xkeenwrt/init/foreign" "$root/etc/init.d/xkeenwrt-ui"
env -u IPKG_INSTROOT PATH="$bin:$PATH" XK_TEST_STATE="$state" "$tmp/package-hook" remove ui
[ "$(readlink "$root/etc/init.d/xkeenwrt-ui")" = "$root/usr/libexec/xkeenwrt/init/foreign" ]
printf 'PACKAGE_HOOK_CONTRACT_PASS=no-rescue-ui-stop,unknown-network-preserved\n'
