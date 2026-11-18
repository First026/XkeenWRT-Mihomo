#!/bin/sh
# Guest setup: official dependencies from signed local indexes, then a LAN
# management client and a WAN DNS peer (pattern of r6-native n02).
set -eu
. /usr/share/xk-lab/lib.sh
R=/usr/share/xk-lab/repo
apk verify $R/core/packages.adb $R/base/packages.adb $R/kmods/packages.adb $R/packages/packages.adb >/dev/null
echo XK_LAB_SIGNED_INDEXES=PASS
grep -qx aarch64_cortex-a53 /etc/apk/arch || echo aarch64_cortex-a53 >> /etc/apk/arch
apk --no-network --repositories-file /dev/null \
  --repository file://$R/core/packages.adb --repository file://$R/base/packages.adb \
  --repository file://$R/kmods/packages.adb --repository file://$R/packages/packages.adb \
  add ip-full kmod-veth kmod-nft-tproxy kmod-nft-socket kmod-nf-conntrack-netlink curl >/tmp/xk-deps.log 2>&1 \
  || { cat /tmp/xk-deps.log; exit 1; }
for m in veth nft_tproxy nft_socket nf_conntrack_netlink; do modprobe "$m"; done
echo XK_LAB_DEPS=PASS
ip=/sbin/ip
/etc/init.d/network stop 2>/dev/null || :
for ns in xk-mgmt xk-peer; do $ip netns del "$ns" 2>/dev/null || :; done
for dev in eth0 wan-host; do $ip link del "$dev" 2>/dev/null || :; done
uci set network.lan.ipaddr='192.168.5.1'
uci set network.lan.netmask='255.255.255.0'
uci -q delete network.lan.ip6assign || :
uci -q delete network.@device[0].ports || :
uci add_list network.@device[0].ports='eth0'
uci -q delete network.wan || :
uci set network.wan='interface'
uci set network.wan.device='wan-host'
uci set network.wan.proto='static'
uci set network.wan.ipaddr='10.0.0.1'
uci set network.wan.netmask='255.255.255.0'
uci set network.wan.gateway='10.0.0.3'
uci commit network
for ns in xk-mgmt xk-peer; do $ip netns add "$ns"; done
$ip link add eth0 type veth peer name mgmt0
$ip link set mgmt0 address 02:00:00:00:00:02
$ip link set eth0 up
$ip link set mgmt0 netns xk-mgmt
$ip netns exec xk-mgmt $ip link set lo up
$ip netns exec xk-mgmt $ip link set mgmt0 up
$ip netns exec xk-mgmt $ip addr add 192.168.5.2/24 dev mgmt0
$ip link add wan-host type veth peer name peer0
$ip link set wan-host up
$ip link set peer0 netns xk-peer
$ip netns exec xk-peer $ip link set lo up
$ip netns exec xk-peer $ip addr add 10.0.0.3/24 dev peer0
$ip netns exec xk-peer $ip link set peer0 up
$ip netns exec xk-peer $ip route replace default via 10.0.0.1 dev peer0
/etc/init.d/network start
sleep 5
/etc/init.d/firewall reload
$ip netns exec xk-mgmt $ip route replace default via 192.168.5.1
$ip netns exec xk-peer /usr/sbin/dnsmasq --no-daemon --no-resolv --no-hosts --bind-interfaces \
  --interface=peer0 --listen-address=10.0.0.3 --port=53 --address=/lab.example/10.0.0.3 >/tmp/xk-peer-dns.log 2>&1 &
echo $! > /tmp/xk-peer-dns.pid
uci set dhcp.@dnsmasq[0].noresolv='1'
uci -q delete dhcp.@dnsmasq[0].resolvfile || :
uci set dhcp.@dnsmasq[0].local='/lan/'
uci set dhcp.@dnsmasq[0].domain='lan'
uci -q delete dhcp.@dnsmasq[0].server || :
uci add_list dhcp.@dnsmasq[0].server='10.0.0.3#53'
uci commit dhcp
/etc/init.d/dnsmasq restart
sleep 2
ubus call network.interface.lan status | grep -q '"up": true'
ubus call network.interface.wan status | grep -q '"up": true'
# A live answer is informational: Start admission checks the upstream configuration.
if $ip netns exec xk-mgmt nslookup lab.example 192.168.5.1 2>/dev/null | grep -q 10.0.0.3; then
  echo XK_LAB_DNS_LIVE=PASS
else
  echo XK_LAB_DNS_LIVE=NOT_ANSWERED
fi
echo XK_LAB_NETWORK=PASS
