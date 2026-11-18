#!/bin/sh
# Install (or upgrade in place to) an exact XkeenWRT pair and make the pinned
# Mihomo 1.19.34 available without network: the ELF is placed at its versioned
# path and selected through the panel, which skips the download when it verifies.
set -eu
. /usr/share/xk-lab/lib.sh
rev=$1
R=/usr/share/xk-lab/repo
A=/usr/share/xk-lab/apks/$rev
apk --no-network --allow-untrusted --force-non-repository --repositories-file /dev/null \
  --repository file://$R/core/packages.adb --repository file://$R/base/packages.adb \
  --repository file://$R/kmods/packages.adb --repository file://$R/packages/packages.adb \
  add "$A/xkeenwrt-core-0.1-$rev.apk" "$A/xkeenwrt-ui-0.1-$rev.apk" >/tmp/xk-install.log 2>&1 \
  || { cat /tmp/xk-install.log; exit 1; }
apk info -v | grep -qx "xkeenwrt-core-0.1-$rev"
apk info -v | grep -qx "xkeenwrt-ui-0.1-$rev"
echo "XK_LAB_INSTALL=$rev"
wait_api
echo XK_LAB_API=READY
cores=/usr/libexec/xkeenwrt/cores
if [ ! -f "$cores/1.19.34/mihomo" ]; then
  mkdir -p "$cores/1.19.34"; chmod 755 "$cores" "$cores/1.19.34"
  cp /usr/share/xk-lab/mihomo "$cores/1.19.34/mihomo"; chmod 755 "$cores/1.19.34/mihomo"
fi
echo '022da41e03ce70641a2f50c485b4f69ade8f1c7aeeece2cf1ec45c614a029441  /usr/libexec/xkeenwrt/cores/1.19.34/mihomo' | sha256sum -c - >/dev/null
cat=$(api GET /api/core/catalog)
if [ "$(field "$cat" '@.integrity')" != verified ]; then
  api POST /api/core/update '{"version":"1.19.34"}' >/dev/null
  n=0; while [ "$n" -lt 60 ]; do
    cat=$(api GET /api/core/catalog); [ "$(field "$cat" '@.integrity')" = verified ] && break
    sleep 2; n=$((n + 1)); done
fi
[ "$(field "$cat" '@.installedVersion')" = 1.19.34 ] || { echo "XK_LAB_MIHOMO=FAIL $cat"; exit 1; }
echo XK_LAB_MIHOMO=VERIFIED
