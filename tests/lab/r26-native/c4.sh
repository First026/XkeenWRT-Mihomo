#!/bin/sh
# C4: the r26 .run installer. Modes:
#   upgrade - r25 is installed: refused while the service runs, then an
#             in-place upgrade after Stop keeps state; a rerun is a no-op.
#   fresh   - nothing installed: a truncated file is refused, then a full
#             install; a rerun is a no-op.
# The installer only accepts the device target, so this lab sets the target
# labels for the run and restores the VM's own labels afterwards.
set -u
. /usr/share/xk-lab/lib.sh
mode=$1
RUN=/usr/share/xk-lab/xkeenwrt-install-r26.run
fail() { restore_labels; echo "XK_LAB_C4=FAIL $*"; exit 1; }
cp /etc/openwrt_release /tmp/openwrt_release.lab
restore_labels() { cp /tmp/openwrt_release.lab /etc/openwrt_release; }
sed -i "s|^DISTRIB_TARGET=.*|DISTRIB_TARGET='mediatek/filogic'|; s|^DISTRIB_ARCH=.*|DISTRIB_ARCH='aarch64_cortex-a53'|" /etc/openwrt_release
case "$mode" in
upgrade)
  apk info -v | grep -qx xkeenwrt-core-0.1-r25 || fail "r25 not installed"
  before_rev=$(field "$(api GET /api/profiles/home)" '@.profile.revision')
  start_gateway >/dev/null || fail "start r25"
  if sh "$RUN" > /tmp/xk-c4-running.out 2>&1; then fail "upgrade accepted while running"; fi
  grep -q 'остановите сервис' /tmp/xk-c4-running.out || { cat /tmp/xk-c4-running.out; fail "refusal text"; }
  apk info -v | grep -qx xkeenwrt-core-0.1-r25 || fail "packages changed by refused run"
  echo XK_LAB_C4_REFUSED_WHILE_RUNNING=PASS
  stop_gateway >/dev/null || fail "stop r25"
  sh "$RUN" > /tmp/xk-c4-upgrade.out 2>&1 || { cat /tmp/xk-c4-upgrade.out; fail "upgrade"; }
  grep -E 'обновлён|Панель' /tmp/xk-c4-upgrade.out
  apk info -v | grep -qx xkeenwrt-core-0.1-r26 && apk info -v | grep -qx xkeenwrt-ui-0.1-r26 || fail "not r26"
  restore_labels
  wait_api || fail api
  [ "$(field "$(api GET /api/core/catalog)" '@.integrity')" = verified ] || fail "mihomo not verified"
  [ "$(field "$(api GET /api/profiles/home)" '@.profile.revision')" = "$before_rev" ] || fail "profile lost"
  apply_profile home "$before_rev" >/dev/null || fail apply
  start_gateway >/dev/null && stop_gateway >/dev/null || fail "cycle after upgrade"
  echo XK_LAB_C4_UPGRADE=PASS
  ;;
fresh)
  apk info -v | grep -q '^xkeenwrt-' && fail "already installed"
  head -c 3000000 "$RUN" > /tmp/truncated.run
  if sh /tmp/truncated.run > /tmp/xk-c4-truncated.out 2>&1; then fail "truncated accepted"; fi
  apk info -v | grep -q '^xkeenwrt-' && fail "truncated installed something"
  echo XK_LAB_C4_TRUNCATED_REFUSED=PASS
  sh "$RUN" > /tmp/xk-c4-fresh.out 2>&1 || { cat /tmp/xk-c4-fresh.out; fail "fresh install"; }
  grep 'Панель' /tmp/xk-c4-fresh.out
  apk info -v | grep -qx xkeenwrt-core-0.1-r26 && apk info -v | grep -qx xkeenwrt-ui-0.1-r26 || fail "not r26"
  echo XK_LAB_C4_FRESH=PASS
  ;;
*) fail "usage: c4.sh upgrade|fresh" ;;
esac
sed -i "s|^DISTRIB_TARGET=.*|DISTRIB_TARGET='mediatek/filogic'|; s|^DISTRIB_ARCH=.*|DISTRIB_ARCH='aarch64_cortex-a53'|" /etc/openwrt_release
sh "$RUN" > /tmp/xk-c4-rerun.out 2>&1 || { cat /tmp/xk-c4-rerun.out; fail "rerun"; }
grep -q 'уже установлен' /tmp/xk-c4-rerun.out || fail "rerun not idempotent"
restore_labels
echo XK_LAB_C4_RERUN=PASS
echo "XK_LAB_C4_$mode=PASS"
