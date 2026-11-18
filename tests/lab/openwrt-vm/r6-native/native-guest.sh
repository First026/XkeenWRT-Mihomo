#!/bin/sh
set -eu
mode=${1:-}
[ "$(id -u)" = 0 ]
[ "$(cat /etc/xkeenwrt-r6-native-lab)" = r6-native-v1 ]
grep -q 'DISTRIB_RELEASE=.25.12.6.' /etc/openwrt_release
[ "$(uname -m)" = aarch64 ]
[ "$(uname -r)" = 6.12.112 ]
case "$mode" in
  n01)
    echo "R6_NATIVE_IDENT=$(uname -m)|$(uname -r)|$(. /etc/openwrt_release; echo "$DISTRIB_RELEASE|$DISTRIB_TARGET|$DISTRIB_ARCH")|$(apk --print-arch)"
    printf '%s  %s\n' 27d61d827d64ccf2f46dce5f52aec6279404d4a00686dafb22f52f3b4ee675f8 /etc/apk/keys/openwrt-25.12.pem | sha256sum -c -
    base=/usr/share/xkeenwrt-r6/repositories
    apk verify "$base/base/packages.adb" "$base/core/packages.adb" "$base/kmods/packages.adb" >/dev/null
    echo R6_NATIVE_SIGNED_INDEXES=PASS
    printf '%s  %s\n' b14951e627892745938334ba0c7074e0b768a8af29d28ba29198ef40933f0d89 /usr/share/xkeenwrt-r6/apks/core.apk | sha256sum -c -
    printf '%s  %s\n' 9e7e0ecfabc7061d730ef5812a31d459111812dfad643c96366af538bfcb3e42 /usr/share/xkeenwrt-r6/apks/ui.apk | sha256sum -c -
    printf '%s\n' aarch64_cortex-a53 >> /etc/apk/arch
    printf '%s\n' \
      'file:///usr/share/xkeenwrt-r6/repositories/base/packages.adb' \
      'file:///usr/share/xkeenwrt-r6/repositories/core/packages.adb' \
      'file:///usr/share/xkeenwrt-r6/repositories/kmods/packages.adb' > /tmp/r6-repositories
    apk --no-network --repositories-file /dev/null \
      --repository file:///usr/share/xkeenwrt-r6/repositories/base/packages.adb \
      --repository file:///usr/share/xkeenwrt-r6/repositories/core/packages.adb \
      --repository file:///usr/share/xkeenwrt-r6/repositories/kmods/packages.adb \
      add ip-full kmod-veth kmod-nft-tproxy kmod-nft-socket > /tmp/r6-official-add.log 2>&1 || { cat /tmp/r6-official-add.log; exit 1; }
    # Stabilize the guest's ordinary fw4/module state before taking the product-only baseline.
    modprobe veth
    modprobe nft_tproxy
    modprobe nft_socket
    /etc/init.d/firewall reload
    sleep 1
    loopback_attempt=0
    while [ "$loopback_attempt" -lt 60 ]; do
      if ubus call network.interface.loopback status | grep -q '"up": true' \
        && /sbin/ip link show lo | grep -q '<.*UP'; then
        break
      fi
      sleep 1
      loopback_attempt=$((loopback_attempt + 1))
    done
    [ "$loopback_attempt" -lt 60 ] || { echo 'R6_NATIVE_BOOT_SETTLED=FAIL'; exit 1; }
    echo 'R6_NATIVE_BOOT_SETTLED=PASS'
    # Take the semantic baseline after installing signed test tools, before product APKs.
    # ip-full owns /sbin/ip via the OpenWrt alternatives database.
    mkdir -p /tmp/r6-baseline
    nft -j list ruleset > /tmp/r6-baseline/nft.json
    /sbin/ip -j link show > /tmp/r6-baseline/links.json
    /sbin/ip -j address show > /tmp/r6-baseline/addresses.json
    /sbin/ip -j rule show > /tmp/r6-baseline/rules4.json
    /sbin/ip -j route show table all > /tmp/r6-baseline/routes4.json
    cp /etc/config/network /tmp/r6-baseline/network
    cp /etc/config/dhcp /tmp/r6-baseline/dhcp
    apk --no-network --allow-untrusted --force-non-repository --repositories-file /dev/null \
      add /usr/share/xkeenwrt-r6/apks/core.apk /usr/share/xkeenwrt-r6/apks/ui.apk > /tmp/r6-product-add.log 2>&1 || { cat /tmp/r6-product-add.log; exit 1; }
    apk info -v | grep -Fxq 'xkeenwrt-core-0.1-r10'
    apk info -v | grep -Fxq 'xkeenwrt-ui-0.1-r10'
    [ "$(cat /etc/apk/arch | tail -n 1)" = aarch64_cortex-a53 ]
    /sbin/ip -j link show > /tmp/r6-after-links.json
    /sbin/ip -j address show > /tmp/r6-after-addresses.json
    nft -j list ruleset > /tmp/r6-after-nft.json
    /sbin/ip -j rule show > /tmp/r6-after-rules4.json
    /sbin/ip -j route show table all > /tmp/r6-after-routes4.json
    cmp /tmp/r6-baseline/links.json /tmp/r6-after-links.json
    cmp /tmp/r6-baseline/addresses.json /tmp/r6-after-addresses.json
    cmp /tmp/r6-baseline/nft.json /tmp/r6-after-nft.json
    cmp /tmp/r6-baseline/rules4.json /tmp/r6-after-rules4.json
    cmp /tmp/r6-baseline/routes4.json /tmp/r6-after-routes4.json
    cmp /tmp/r6-baseline/network /etc/config/network
    cmp /tmp/r6-baseline/dhcp /etc/config/dhcp
    [ ! -e /etc/xkeenwrt/runtime-enabled ]
    [ ! -e /etc/xkeenwrt/recovery-enabled ]
    ! pidof mihomo >/dev/null 2>&1
    ! pidof xkeenwrt-ui >/dev/null 2>&1
    for service in xkeenwrt-runtime xkeenwrt-ui xkeenwrt-core xkeenwrt-recovery; do
      for link in /etc/rc.d/S*"$service"; do [ ! -L "$link" ] || exit 1; done
    done
    echo 'R6_NATIVE_INSTALL=inert'
    echo 'R6_NATIVE_ARCH_ADJUST=aarch64_generic+aarch64_cortex-a53'
    echo 'R6_NATIVE_N01=PASS'
    ;;
  n02) exec /usr/libexec/xkeenwrt-r6-native/n02.sh ;;
  *) echo 'usage: native-guest.sh n01|n02' >&2; exit 2 ;;
esac
