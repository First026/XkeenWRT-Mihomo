#!/bin/sh
# C1: upgrade 0.1.26.3 -> 0.1.26.4 with the release .run installer after a
# stopped LAN generation; rescue 0.1.26.4 reads the kept journal, profiles and
# Mihomo survive, and Start from the LAN works without a management channel.
# The installer accepts only the device target, so labels are set for its run.
set -u
. /usr/share/xk-lab/lib.sh
restore() { [ -f /tmp/openwrt_release.lab ] && cp /tmp/openwrt_release.lab /etc/openwrt_release; }
fail() { restore; echo "XK_LAB_C1=FAIL $*"; exit 1; }
apk info -v | grep -q '^xkeenwrt-' && fail "not a fresh disk"
sh /usr/share/xk-lab/install.sh r26.3 0.1.26.3-r0 > /tmp/xk-c1-old.out 2>&1 || { cat /tmp/xk-c1-old.out; fail "install 0.1.26.3"; }
grep XK_LAB /tmp/xk-c1-old.out
use_lan
rev=$(save_profile home "$PROFILE"); [ -n "$rev" ] || fail profile
apply_profile home "$rev" || fail apply
start_gateway || fail "start 0.1.26.3"
[ "$(lan_fetch)" != 000 ] || fail "0.1.26.3 gateway did not carry the LAN client"
stop_gateway || fail "stop 0.1.26.3"
grep -q management_channel $ROOT/recovery.json && fail "0.1.26.3 journal has a channel"
owner=$(cat $ROOT/owner-id)
cp /etc/openwrt_release /tmp/openwrt_release.lab
sed -i "s|^DISTRIB_TARGET=.*|DISTRIB_TARGET='mediatek/filogic'|; s|^DISTRIB_ARCH=.*|DISTRIB_ARCH='aarch64_cortex-a53'|" /etc/openwrt_release
sh /usr/share/xk-lab/xkeenwrt-install-r26.4.run > /tmp/xk-c1-upgrade.out 2>&1 || { cat /tmp/xk-c1-upgrade.out; fail upgrade; }
restore
grep -q 'обновлён с 0.1.26.3-r0 до 0.1.26.4-r0' /tmp/xk-c1-upgrade.out || { cat /tmp/xk-c1-upgrade.out; fail "upgrade text"; }
apk info -v | grep -qx xkeenwrt-core-0.1.26.4-r0 && apk info -v | grep -qx xkeenwrt-ui-0.1.26.4-r0 || fail "not 0.1.26.4"
[ "$(cat $ROOT/owner-id)" = "$owner" ] || fail "owner changed"
wait_api || fail api
[ "$(field "$(api GET /api/core/catalog)" '@.integrity')" = verified ] || fail "mihomo not verified"
[ "$(field "$(api GET /api/profiles/home)" '@.profile.revision')" = "$rev" ] || fail "profile not kept"
references_intact || fail dangling
no_recovery_crash || fail "recovery stopped after upgrade"
echo XK_LAB_C1_UPGRADE=PASS
start_gateway || fail "LAN start on 0.1.26.4"
[ "$(lan_fetch)" != 000 ] || fail "LAN client on 0.1.26.4"
grep -q management_channel $ROOT/recovery.json && fail "LAN start recorded a channel"
stop_gateway || fail "LAN stop"
own_table_absent || fail "own nft table left"
no_recovery_crash || fail "recovery stopped"
echo XK_LAB_C1=PASS
