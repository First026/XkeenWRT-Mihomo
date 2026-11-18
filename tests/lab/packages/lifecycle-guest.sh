#!/bin/sh
# Executed only in disposable OpenWrt VM without network devices.
set -eu
fail() { echo "LIFECYCLE_FAIL:$*"; exit 1; }
[ "$(uname -m)" = x86_64 ] || fail arch
[ "$(ls /sys/class/net | tr '\n' ' ')" = 'lo ' ] || fail net
cd /usr/share/xkeen-lab-packages
add() { apk add --no-network --allow-untrusted --force-non-repository "$@" >/tmp/xkeen-apk.log 2>&1 || { cat /tmp/xkeen-apk.log; fail apk-add; }; }
add ./xkeenwrt-core-0.1-r1.apk ./xkeenwrt-ui-0.1-r1.apk
[ -x /usr/libexec/xkeenwrt/mihomo ] && [ -x /usr/bin/xkeenwrt-ui ] || fail payload
[ "$(/usr/bin/xkeenwrt-ui package-version)" = 0.1-r1 ] || fail backend-version-install
cmp -s /usr/share/xkeenwrt/ui-manifest.json /usr/share/xkeenwrt/core-manifest.json || fail manifest-install
/usr/bin/xkeenwrt-ui package-check || fail package-check-install
cp -p /usr/bin/xkeenwrt-ui /tmp/xkeen-original-ui
printf x >> /usr/bin/xkeenwrt-ui
if /usr/bin/xkeenwrt-ui package-check >/dev/null 2>&1; then fail changed-payload-accepted; fi
cp -p /tmp/xkeen-original-ui /usr/bin/xkeenwrt-ui
rm -f /tmp/xkeen-original-ui
/usr/bin/xkeenwrt-ui package-check || fail payload-restoration
for file in /usr/libexec/xkeenwrt/xkeenwrt-validate /usr/libexec/xkeenwrt/init/xkeenwrt-core; do
  cp -p "$file" /tmp/xkeen-original-component
  printf x >> "$file"
  if /usr/bin/xkeenwrt-ui package-check >/dev/null 2>&1; then fail changed-component-accepted; fi
  cp -p /tmp/xkeen-original-component "$file"
  rm -f /tmp/xkeen-original-component
done
/usr/bin/xkeenwrt-ui package-check || fail component-restoration
rm /etc/init.d/xkeenwrt-core
ln -s /usr/libexec/xkeenwrt/init/xkeenwrt-ui /etc/init.d/xkeenwrt-core
if /usr/bin/xkeenwrt-ui package-check >/dev/null 2>&1; then fail foreign-init-link-accepted; fi
rm /etc/init.d/xkeenwrt-core
ln -s /usr/libexec/xkeenwrt/init/xkeenwrt-core /etc/init.d/xkeenwrt-core
/usr/bin/xkeenwrt-ui package-check || fail init-link-restoration
echo 'LIFECYCLE_TAMPER_GUARD=PASS'  
[ -L /etc/init.d/xkeenwrt-core ] && [ -L /etc/init.d/xkeenwrt-runtime ] || fail init-links
[ "$(cat /lib/upgrade/keep.d/xkeenwrt)" = /etc/xkeenwrt/ ] || fail sysupgrade-keep-list
[ ! -e /etc/xkeenwrt/runtime-enabled ] && [ ! -e /etc/xkeenwrt/recovery-enabled ] || fail auto-enable
[ ! -e /etc/rc.d/S90xkeenwrt-runtime ] && [ ! -e /etc/rc.d/S91xkeenwrt-ui ] || fail auto-boot
! pidof mihomo >/dev/null || fail core-running
! pidof xkeenwrt-ui >/dev/null || fail ui-running
echo 'LIFECYCLE_INSTALL=PASS'
mkdir -p /etc/xkeenwrt/history /etc/xkeenwrt/other
chmod 700 /etc/xkeenwrt
printf 'synthetic profile\n' > /etc/xkeenwrt/config.yaml
printf 'synthetic history\n' > /etc/xkeenwrt/history/test-snapshot
printf 'foreign sentinel\n' > /etc/xkeenwrt/other/sentinel
add ./xkeenwrt-core-0.1-r2.apk ./xkeenwrt-ui-0.1-r2.apk
[ "$(/usr/bin/xkeenwrt-ui package-version)" = 0.1-r2 ] || fail backend-version-upgrade
cmp -s /usr/share/xkeenwrt/ui-manifest.json /usr/share/xkeenwrt/core-manifest.json || fail manifest-upgrade
/usr/bin/xkeenwrt-ui package-check || fail package-check-upgrade
[ "$(cat /etc/xkeenwrt/config.yaml)" = 'synthetic profile' ] || fail upgrade-config
[ "$(cat /etc/xkeenwrt/history/test-snapshot)" = 'synthetic history' ] || fail upgrade-history
! pidof mihomo >/dev/null || fail upgrade-core-start
! pidof xkeenwrt-ui >/dev/null || fail upgrade-ui-start
echo 'LIFECYCLE_UPGRADE=PASS'
apk del --no-network xkeenwrt-ui xkeenwrt-core >/tmp/xkeen-apk-del.log 2>&1 || { cat /tmp/xkeen-apk-del.log; fail apk-del; }
[ ! -e /usr/bin/xkeenwrt-ui ] && [ ! -e /usr/libexec/xkeenwrt/mihomo ] || fail removal-payload
[ ! -L /etc/init.d/xkeenwrt-core ] && [ ! -L /etc/init.d/xkeenwrt-runtime ] || fail removal-init
[ "$(cat /etc/xkeenwrt/config.yaml)" = 'synthetic profile' ] || fail removal-config
[ "$(cat /etc/xkeenwrt/history/test-snapshot)" = 'synthetic history' ] || fail removal-history
[ "$(cat /etc/xkeenwrt/other/sentinel)" = 'foreign sentinel' ] || fail removal-foreign
echo 'LIFECYCLE_REMOVE=PASS'
add ./xkeenwrt-core-0.1-r1.apk ./xkeenwrt-ui-0.1-r1.apk
[ "$(/usr/bin/xkeenwrt-ui package-version)" = 0.1-r1 ] || fail backend-version-reinstall
/usr/bin/xkeenwrt-ui package-check || fail package-check-reinstall
[ "$(cat /etc/xkeenwrt/config.yaml)" = 'synthetic profile' ] || fail reinstall-config
[ ! -e /etc/xkeenwrt/runtime-enabled ] && [ ! -e /etc/xkeenwrt/recovery-enabled ] || fail reinstall-enable
! pidof mihomo >/dev/null || fail reinstall-core-start
! pidof xkeenwrt-ui >/dev/null || fail reinstall-ui-start
echo 'LIFECYCLE_REINSTALL=PASS'
# Limit just the package's executable directory; the guest and its database stay writable.
old_hash=$(sha256sum /usr/libexec/xkeenwrt/mihomo | cut -d ' ' -f 1)
mount -t tmpfs -o size=64k tmpfs /usr/libexec/xkeenwrt || fail enospc-mount
if apk add --no-network --allow-untrusted --force-non-repository ./xkeenwrt-core-0.1-r2.apk ./xkeenwrt-ui-0.1-r2.apk >/tmp/xkeen-enospc.log 2>&1; then
  upgrade_status=0
else
  upgrade_status=$?
fi
umount /usr/libexec/xkeenwrt || fail enospc-umount
printf 'LIFECYCLE_ENOSPC_EXIT=%s\n' "$upgrade_status"
[ "$upgrade_status" != 0 ] || fail enospc-not-triggered
grep -q 'No space left on device' /tmp/xkeen-enospc.log || { cat /tmp/xkeen-enospc.log; fail enospc-not-proven; }
echo 'LIFECYCLE_ENOSPC_ERROR=confirmed'
if [ -f /usr/libexec/xkeenwrt/mihomo ] && [ "$(sha256sum /usr/libexec/xkeenwrt/mihomo | cut -d ' ' -f 1)" = "$old_hash" ]; then
  echo 'LIFECYCLE_ENOSPC_OLD_CORE=present'
else
  echo 'LIFECYCLE_ENOSPC_OLD_CORE=missing-or-changed'
fi
printf 'LIFECYCLE_ENOSPC_VERSIONS='; apk info -v 2>/dev/null | grep '^xkeenwrt-' | tr '\n' ','; echo
[ "$(cat /etc/xkeenwrt/config.yaml)" = 'synthetic profile' ] || fail enospc-config
[ "$(cat /etc/xkeenwrt/history/test-snapshot)" = 'synthetic history' ] || fail enospc-history
echo 'LIFECYCLE_ENOSPC_DATA=preserved'
if /usr/bin/xkeenwrt-ui package-check >/dev/null 2>&1; then fail enospc-pair-accepted; fi
echo 'LIFECYCLE_ENOSPC_GUARD=PASS'
echo 'LIFECYCLE_DONE=PASS' 
