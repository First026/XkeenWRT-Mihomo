#!/usr/bin/env bash
# Disposable netns lab: br-lan with eth1 (cable) and phy1-ap0 (Wi-Fi port with
# an active client). Captures the exact helper inventory queries per step.
# Run only as root in a disposable container or VM, never on a router.
# Usage: netns-capture.sh OUT_DIR [disabled|enabled]
#   The second argument sets IPv6 on bridge ports; "disabled" assumes the
#   netifd bridge-member behaviour, which the bench check must confirm.
set -euo pipefail
out=${1:?output dir}
ipv6_members=${2:-disabled}
rm -rf "$out"; mkdir -p "$out"
R=xk-router W=xk-wire C=xk-wifi
cleanup() { for n in $R $W $C; do ip netns del $n 2>/dev/null || true; done; }
trap cleanup EXIT
cleanup
for n in $R $W $C; do ip netns add $n; done
r() { ip netns exec $R "$@"; }
r ip link set lo up
r ip link add br-lan type bridge
r ip link set br-lan address 02:00:00:00:10:02
# WAN port without carrier (peer never up), like a router's unplugged eth0.
r ip link add eth0 address 02:00:00:00:10:01 type veth peer name wan-peer
r ip link set eth0 up
# Cable: eth1 <-> pc0 in the "wire" namespace (a wired PC).
r ip link add eth1 address 02:00:00:00:10:12 type veth peer name pc0 netns $W
# Wi-Fi AP port: phy1-ap0 <-> sta0 in the "wifi" namespace (active client).
r ip link add phy1-ap0 address 02:00:00:00:10:03 type veth peer name sta0 netns $C
for p in eth1 phy1-ap0; do
  if [[ $ipv6_members == disabled && -d /proc/sys/net/ipv6 ]]; then r sysctl -qw net.ipv6.conf.$p.disable_ipv6=1; fi
  r ip link set $p master br-lan
  r ip link set $p up
done
r ip link set br-lan up
r ip addr add 192.168.5.1/24 dev br-lan
ip netns exec $C ip link set lo up
ip netns exec $C ip link set sta0 up
ip netns exec $C ip addr add 192.168.5.20/24 dev sta0
ip netns exec $W ip link set lo up
ip netns exec $W ip addr add 192.168.5.30/24 dev pc0
# Cable starts unplugged: the PC end is down, so eth1 has no carrier.
ip netns exec $W ip link set pc0 down
sleep 3
ip netns exec $C ping -c1 -W2 192.168.5.1 >/dev/null

snap() {
  local d=$out/$1; mkdir -p "$d"
  r ip -j link show >"$d/links.json"
  r ip -j address show >"$d/addresses.json"
  r ip -j -4 route show table all >"$d/routes4.json"
  r ip -j -6 route show table all >"$d/routes6.json"
  r ip -j neigh show >"$d/neighbours.json"
  ip netns exec $C ping -c1 -W2 192.168.5.1 >/dev/null && echo up >"$d/wifi-client" || echo down >"$d/wifi-client"
  echo "$2" >"$d/expect"
}
plug()   { ip netns exec $W ip link set pc0 up; sleep 3; }
unplug() { ip netns exec $W ip link set pc0 down; sleep 3; }

snap 00-pinned-unplugged same
plug;   ip netns exec $W ping -c1 -W2 192.168.5.1 >/dev/null; snap 01-cable-plugged same
unplug; snap 02-cable-unplugged same
plug;   snap 03-cable-replugged same
# Flap within one second, as a PHY renegotiation would.
ip netns exec $W ip link set pc0 down; ip netns exec $W ip link set pc0 up; sleep 1; snap 04-cable-flap same
unplug; snap 05-back-to-pinned same
# Real topology changes must still drift.
r ip link set eth1 nomaster; sleep 1; snap 10-eth1-left-bridge drift
r ip link set eth1 master br-lan; sleep 1; snap 11-eth1-rejoined same
r ip link add lan9 address 02:00:00:00:10:09 type veth peer name lan9-peer
[[ $ipv6_members == disabled && -d /proc/sys/net/ipv6 ]] && r sysctl -qw net.ipv6.conf.lan9.disable_ipv6=1
r ip link set lan9 master br-lan; r ip link set lan9 up; sleep 1; snap 12-new-bridge-port drift
r ip link del lan9; sleep 1; snap 13-port-removed same
r ip link set eth1 down; sleep 1; snap 14-eth1-admin-down drift
r ip link set eth1 up; sleep 1; snap 15-eth1-admin-up same
r ip link set eth1 address 02:00:00:00:10:99; sleep 1; snap 16-eth1-mac-changed drift
r ip link set eth1 address 02:00:00:00:10:12; sleep 1; snap 17-eth1-mac-restored same
r ip link del phy1-ap0
r ip link add phy1-ap0 address 02:00:00:00:10:03 type veth peer name sta0 netns $C
[[ $ipv6_members == disabled && -d /proc/sys/net/ipv6 ]] && r sysctl -qw net.ipv6.conf.phy1-ap0.disable_ipv6=1
r ip link set phy1-ap0 master br-lan; r ip link set phy1-ap0 up
ip netns exec $C ip link set sta0 up; ip netns exec $C ip addr add 192.168.5.20/24 dev sta0
sleep 3; snap 18-wifi-port-recreated drift
r ip addr add 192.168.5.2/24 dev br-lan; sleep 1; snap 19-second-lan-address drift
echo "captured $(ls "$out" | wc -l) steps into $out"
