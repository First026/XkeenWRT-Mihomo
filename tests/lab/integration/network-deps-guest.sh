#!/bin/sh
set -eu
stage=identity
trap 'printf "NETWORK_DEPS_FAIL=%s\n" "$stage"' EXIT
[ "$(id -u)" = 0 ]
[ "$(uname -m)" = x86_64 ] && [ "$(uname -r)" = 6.12.112 ]
[ "$(. /etc/openwrt_release; echo "$DISTRIB_REVISION|$DISTRIB_TARGET")" = 'r33311-981c978eff|x86/64' ]
[ "$(cat /etc/xkeenwrt-isolation-lab)" = xkeenwrt-validator-lab-v1 ]
grep -qw xkeenwrt.isolation_lab=1 /proc/cmdline
[ "$(ls /sys/class/net)" = lo ]
stage=kernelpackage
apk info -v | grep -Fxq 'kernel-6.12.112~b4125196ecec75391093e1e2edeba490-r1'
stage=indexsignature
cd /usr/share/xkeenwrt-network-lab
for index in indexes/x86-base.adb indexes/x86-core.adb indexes/x86-kmods.adb; do
  apk verify "$index" >/dev/null 2>&1
done
echo NETWORK_DEPS_SIGNATURE=PASS
stage=repository
for repo in base core kmods; do
  mkdir -p "/tmp/xkeenwrt-local-repos/$repo"
  cp "indexes/x86-$repo.adb" "/tmp/xkeenwrt-local-repos/$repo/packages.adb"
  cp ./*.apk "/tmp/xkeenwrt-local-repos/$repo/"
done
stage=install
apk --no-network --repositories-file /dev/null \
  --repository file:///tmp/xkeenwrt-local-repos/base/packages.adb \
  --repository file:///tmp/xkeenwrt-local-repos/core/packages.adb \
  --repository file:///tmp/xkeenwrt-local-repos/kmods/packages.adb \
  add ip-full kmod-veth kmod-nft-tproxy kmod-nft-socket > /tmp/xkeen-network-apk.log 2>&1 || {
    cat /tmp/xkeen-network-apk.log; exit 1;
  }
echo NETWORK_DEPS_INSTALL=PASS
stage=modules
modprobe veth
modprobe nft_tproxy
modprobe nft_socket
ip link add xkeen-probe0 type veth peer name xkeen-probe1
ip link del xkeen-probe0
printf '%s\n' \
  'table inet xkeenwrt_probe {' \
  ' chain test {' \
  '  type filter hook prerouting priority mangle;' \
  '  tcp dport 12345 tproxy to :12345 accept' \
  ' }' \
  '}' >/tmp/xkeen-network-probe.nft
nft -c -f /tmp/xkeen-network-probe.nft >/dev/null
echo NETWORK_DEPS_TPROXY_VETH=PASS
[ "$(ls /sys/class/net)" = lo ]
[ "$(cat /proc/1/comm)" = procd ]
ubus call system board >/dev/null
[ "$(cat /tmp/xkeenwrt-test-sentinel)" = test-sentinel-v1 ]
trap - EXIT
echo NETWORK_DEPS_ALL_PASS
