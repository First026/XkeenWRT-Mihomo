#!/bin/sh
# Guest setup for 0.1.26.2: the r26 stand (signed local dependencies, a LAN
# management client, a WAN DNS peer) plus
#  - a Tailscale-like management path: tailscale0 is a veth whose peer
#    namespace xk-ts stands for an administrator (100.64.20.2) in the tailnet;
#  - a lab "internet" behind the WAN peer: www.gstatic.com on 1.2.3.4 over
#    HTTPS (lab CA), reachable only through a Shadowsocks proxy on 10.0.0.3,
#    and a plain site on 1.2.3.5 reachable directly, so the profile rules
#    show which connection went through the proxy and which went DIRECT.
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
# A rerun replaces the lab helpers of the previous run (they outlive their netns).
for pid in $(pgrep -f '^/usr/share/xk-lab/lab-peer -d /tmp/xk-peer-mihomo') $(pgrep -f '^/usr/share/xk-lab/lab-site -d /tmp/xk-peer-site') $(cat /tmp/xk-peer-dns.pid 2>/dev/null); do
  kill "$pid" 2>/dev/null || :
done
/etc/init.d/network stop 2>/dev/null || :
for ns in xk-mgmt xk-peer xk-ts; do $ip netns del "$ns" 2>/dev/null || :; done
for dev in eth0 wan-host tailscale0; do $ip link del "$dev" 2>/dev/null || :; done
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
# As on the device: network 'tailscale' (proto none, device tailscale0) in the LAN zone.
uci -q delete network.tailscale || :
uci set network.tailscale='interface'
uci set network.tailscale.proto='none'
uci set network.tailscale.device='tailscale0'
uci commit network
[ "$(uci get firewall.@zone[0].name)" = lan ] || { echo XK_LAB_ZONE=NOT_LAN; exit 1; }
uci -q del_list firewall.@zone[0].network='tailscale' || :
uci add_list firewall.@zone[0].network='tailscale'
uci commit firewall
for ns in xk-mgmt xk-peer xk-ts; do $ip netns add "$ns"; done
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
$ip link add tailscale0 type veth peer name tsp0
$ip link set tsp0 netns xk-ts
$ip netns exec xk-ts $ip link set lo up
$ip netns exec xk-ts $ip link set tsp0 up
$ip netns exec xk-ts $ip addr add 100.64.20.2/32 dev tsp0
$ip netns exec xk-ts $ip route replace 100.64.10.1/32 dev tsp0
/etc/init.d/network start
sleep 5
# netifd sometimes misses 'tailscale' on the first start, and a reload drops
# the manual address: wait for the interface, then assign address and route
# (tailscaled does this on the device) and let fw4 pick up tailscale0 in the LAN zone.
n=0; until ubus call network.interface.tailscale status 2>/dev/null | grep -q '"up": true' || [ "$n" -ge 10 ]; do
  ubus call network reload; sleep 3; n=$((n + 1)); done
$ip link set tailscale0 up
$ip addr replace 100.64.10.1/32 dev tailscale0
$ip route replace 100.64.20.2/32 dev tailscale0
/etc/init.d/firewall reload
$ip netns exec xk-mgmt $ip route replace default via 192.168.5.1
# The LAN client resolves through the router, like a DHCP client would.
mkdir -p /etc/netns/xk-mgmt
echo 'nameserver 192.168.5.1' > /etc/netns/xk-mgmt/resolv.conf
# Lab "internet": the blocked site lives on the peer's loopback. It needs a
# public-looking address: OpenWrt's dnsmasq rebind protection drops upstream
# answers in private and TEST-NET ranges (10/8, 198.51.100/24, ...), as on the device.
$ip netns exec xk-peer $ip addr add 1.2.3.4/32 dev lo
$ip netns exec xk-peer $ip addr add 1.2.3.5/32 dev lo
mkdir -p /etc/netns/xk-peer
# Peer-local lookups reach its dnsmasq over lo; the 10.0.0.3 bind serves peer0 only.
echo 'nameserver 127.0.0.1' > /etc/netns/xk-peer/resolv.conf
start_peer_dns
# Direct LAN traffic to the site is dropped at the peer; only the proxy reaches it.
$ip netns exec xk-peer nft -f - <<'NFT'
table inet xklab {
  chain input {
    type filter hook input priority 0; policy accept;
    iifname "peer0" ip daddr 1.2.3.4 tcp dport 443 drop
  }
}
NFT
# Lab CA trusted by the guest (Mihomo uses the system pool, curl the same bundle).
touch /etc/ssl/certs/ca-certificates.crt
grep -q 'XkeenWRT lab CA' /etc/ssl/certs/ca-certificates.crt 2>/dev/null || {
  printf '# XkeenWRT lab CA\n' >> /etc/ssl/certs/ca-certificates.crt
  cat /usr/share/xk-lab/tls/ca.crt >> /etc/ssl/certs/ca-certificates.crt; }
start_peer_proxy
start_peer_site
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
n=0; until $ip netns exec xk-ts ping -c 1 -W 2 100.64.10.1 >/dev/null 2>&1 || [ "$n" -ge 10 ]; do sleep 2; n=$((n + 1)); done
$ip netns exec xk-ts ping -c 1 -W 2 100.64.10.1 >/dev/null && echo XK_LAB_TAILNET=PASS || { echo XK_LAB_TAILNET=FAIL; exit 1; }
# Before any gateway the proxied site is unreachable and the plain site is open.
[ "$(lan_fetch)" = 000 ] && echo XK_LAB_SITE_BLOCKED_DIRECT=PASS || { echo XK_LAB_SITE_BLOCKED_DIRECT=FAIL; exit 1; }
[ "$(lan_fetch_direct)" != 000 ] && echo XK_LAB_PLAIN_SITE_OPEN=PASS || { echo XK_LAB_PLAIN_SITE_OPEN=FAIL; exit 1; }
echo XK_LAB_NETWORK=PASS
