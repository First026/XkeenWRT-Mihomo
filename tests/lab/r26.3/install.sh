#!/bin/sh
# Install (or upgrade in place to) an exact XkeenWRT pair from the lab copy and
# make the pinned Mihomo 1.19.34 available without network.
# Usage: install.sh DIR VERSION   e.g. install.sh r26 0.1-r26
set -eu
. /usr/share/xk-lab/lib.sh
dir=$1 version=$2
R=/usr/share/xk-lab/repo
A=/usr/share/xk-lab/apks/$dir
apk --no-network --allow-untrusted --force-non-repository --repositories-file /dev/null \
  --repository file://$R/core/packages.adb --repository file://$R/base/packages.adb \
  --repository file://$R/kmods/packages.adb --repository file://$R/packages/packages.adb \
  add "$A/xkeenwrt-core-$version.apk" "$A/xkeenwrt-ui-$version.apk" >/tmp/xk-install.log 2>&1 \
  || { cat /tmp/xk-install.log; exit 1; }
apk info -v | grep -qx "xkeenwrt-core-$version"
apk info -v | grep -qx "xkeenwrt-ui-$version"
echo "XK_LAB_INSTALL=$version"
use_lan
wait_api
echo XK_LAB_API=READY
ensure_mihomo
