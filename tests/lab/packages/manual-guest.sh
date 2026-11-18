#!/bin/sh
# Only a synthetic, no-NIC OpenWrt VM. Packages must already be in guest image.
set -eu
fail() { echo "MANUAL_FAIL:$*"; exit 1; }
grep -qw xkeenwrt.isolation_lab=1 /proc/cmdline || fail isolation
cd /usr/share/xkeen-lab-packages
apk add --no-network --allow-untrusted --force-non-repository ./xkeenwrt-core-0.1-r1.apk ./xkeenwrt-ui-0.1-r1.apk >/tmp/xkeen-manual-apk.log 2>&1 || { cat /tmp/xkeen-manual-apk.log; fail install; }
./runtime-package-smoke.sh || fail manual-runtime
[ -x /etc/xkeenwrt/rescue/xkeenwrt-recovery ] || fail rescue-provision
printf 'synthetic survivor\n' > /etc/xkeenwrt/package-test-sentinel
apk del --no-network xkeenwrt-ui xkeenwrt-core >/tmp/xkeen-manual-remove.log 2>&1 || { cat /tmp/xkeen-manual-remove.log; fail remove; }
[ ! -e /usr/bin/xkeenwrt-ui ] && [ ! -e /usr/libexec/xkeenwrt/mihomo ] || fail payload-present
[ -x /etc/xkeenwrt/rescue/xkeenwrt-recovery ] || fail rescue-removed
[ "$(cat /etc/xkeenwrt/package-test-sentinel)" = 'synthetic survivor' ] || fail state-removed
/etc/xkeenwrt/rescue/xkeenwrt-recovery --remove-status > /tmp/xkeen-manual-status || fail rescue-status
[ "$(jsonfilter -i /tmp/xkeen-manual-status -e '@.kind')" = remove ] || fail wrong-kind
[ "$(jsonfilter -i /tmp/xkeen-manual-status -e '@.state')" = cleanup_complete ] || fail incomplete-cleanup
! pidof mihomo >/dev/null || fail core-still-running
! pidof xkeenwrt-ui >/dev/null || fail runtime-still-running
printf 'MANUAL_PACKAGE_PASS=install,manual-start-stop,active-remove,rescue-retained,cleanup-complete\n'
