#!/bin/sh
# C9 (decision 026): panel self-update from the tailnet, as the owner manages
# the router. A lab GitHub on the WAN peer (github.sh: api.github.com,
# raw.githubusercontent.com and github.com on 1.2.3.6, lab CA) lists 0.1.26.3,
# 0.1.26.4 and the lab-only 0.1.26.4.1 and serves the 0.1.26.4.1 installer and
# APKs. The panel offers only 0.1.26.4.1, refuses a running gateway, older and
# unknown versions, then runs the release's own installer in a transient procd
# service: the APK upgrade restarts the panel, the installer finishes, owner,
# profile and Mihomo survive, the new panel reports the result and LAN Start
# works on 0.1.26.4.1. The installer accepts only the device target, so labels
# are set for its run, as in C1.
set -u
. /usr/share/xk-lab/lib.sh
new=0.1.26.4.1
restore() { [ -f /tmp/openwrt_release.lab ] && cp /tmp/openwrt_release.lab /etc/openwrt_release; rm -f /tmp/openwrt_release.lab; }
fail() { restore; stop_peer_github; echo "XK_LAB_C9=FAIL $*"; exit 1; }
apk info -v | grep -qx xkeenwrt-ui-0.1.26.4-r0 || { echo "XK_LAB_C9=FAIL 0.1.26.4 is not installed"; exit 1; }
start_peer_github || fail "lab GitHub"
use_lan; wait_api || fail "LAN listener"
rev=$(field "$(api GET /api/profiles/home)" '@.profile.revision'); [ -n "$rev" ] || fail profile
owner=$(cat $ROOT/owner-id)
use_ts; wait_api || fail "tailnet listener"
cat=$(api GET /api/self/catalog)
[ "$(code)" = 200 ] && [ "$(field "$cat" '@.current')" = 0.1.26.4 ] || fail "catalog code=$(code) $cat"
offered=$(field "$cat" '@.releases[*].version' | tr '\n' ' ')
[ "$offered" = "0.1.26.4 $new " ] || fail "catalog offers: $offered"
echo "XK_LAB_C9_CATALOG=PASS offered=$offered"

start_gateway || fail "start before the refusal"
out=$(api POST /api/self/update "{\"version\":\"$new\"}")
[ "$(code)" = 409 ] && [ "$(field "$out" '@.code')" = GATEWAY_RUNNING ] || fail "running gateway: code=$(code) $out"
stop_gateway || fail stop
for v in 0.1.26.4 0.1.26.3; do
  out=$(api POST /api/self/update "{\"version\":\"$v\"}")
  [ "$(code)" = 400 ] && [ "$(field "$out" '@.code')" = NOT_NEWER ] || fail "version $v: code=$(code) $out"
done
out=$(api POST /api/self/update '{"version":"0.1.26.9"}')
[ "$(code)" = 400 ] && [ "$(field "$out" '@.code')" = UNKNOWN_RELEASE ] || fail "unknown release: code=$(code) $out"
[ "$(field "$(api GET /api/self/update/status)" '@.state')" = idle ] || fail "a refused request left a run"
echo XK_LAB_C9_REFUSED=PASS

cp /etc/openwrt_release /tmp/openwrt_release.lab
sed -i "s|^DISTRIB_TARGET=.*|DISTRIB_TARGET='mediatek/filogic'|; s|^DISTRIB_ARCH=.*|DISTRIB_ARCH='aarch64_cortex-a53'|" /etc/openwrt_release
out=$(api POST /api/self/update "{\"version\":\"$new\"}")
[ "$(code)" = 200 ] || fail "update start code=$(code) $out"
down=0 n=0 final=
while [ "$n" -lt 600 ]; do
  st=$(api GET /api/self/update/status)
  if [ "$(code)" != 200 ]; then
    down=$((down + 1))
  else
    case "$(field "$st" '@.state')" in
      done) [ "$(field "$st" '@.current')" = "$new-r0" ] && { final=$st; break; } ;;
      failed|interrupted) fail "installer: $st" ;;
    esac
  fi
  sleep 2; n=$((n + 2))
done
restore
[ -n "$final" ] || fail "no result after ${n}s: $st"
echo "XK_LAB_C9_UPDATED=PASS after=${n}s unanswered_polls=$down"
field "$final" '@.log[*]' | grep -q "обновлён с 0.1.26.4-r0 до $new-r0" || fail "installer text: $final"
apk info -v | grep -qx "xkeenwrt-core-$new-r0" && apk info -v | grep -qx "xkeenwrt-ui-$new-r0" || fail "not $new"
[ "$(cat $ROOT/owner-id)" = "$owner" ] || fail "owner changed"
ubus call service list '{"name":"xkeenwrt-self-update"}' | grep -q xkeenwrt-self-update && fail "transient service left"
stop_peer_github

use_lan; wait_api || fail "LAN listener on $new"
[ "$(field "$(api GET /api/app-info)" '@.package_version')" = "$new-r0" ] || fail "panel version"
[ "$(field "$(api GET /api/core/catalog)" '@.integrity')" = verified ] || fail "mihomo not verified"
[ "$(field "$(api GET /api/profiles/home)" '@.profile.revision')" = "$rev" ] || fail "profile not kept"
references_intact || fail dangling
no_recovery_crash || fail "recovery stopped after the update"
echo XK_LAB_C9_KEPT=PASS
start_gateway || fail "LAN start on $new"
[ "$(lan_fetch)" != 000 ] || fail "LAN client on $new"
stop_gateway || fail "LAN stop on $new"
own_table_absent || fail "own nft table left"
echo XK_LAB_C9=PASS
