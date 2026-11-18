#!/bin/sh
# Все ключи синтетические; запуск разрешён только в маркированной одноразовой VM.
set -eu
grep -qw 'xkeenwrt.isolation_lab=1' /proc/cmdline
[ "$(cat /etc/xkeenwrt-isolation-lab)" = 'xkeenwrt-validator-lab-v1' ]
stage=loopback
peer=
core=
stop_child() {
  pid=$1
  [ -n "$pid" ] || return 0
  kill "$pid" 2>/dev/null || :
  for n in 1 2 3; do kill -0 "$pid" 2>/dev/null || break; sleep 1; done
  kill -9 "$pid" 2>/dev/null || :
  wait "$pid" 2>/dev/null || :
}
cleanup() {
  stop_child "$core"
  stop_child "$peer"
}
fail() { printf 'LAB_AWG_FAIL=%s\n' "$stage"; cleanup; }
trap fail EXIT HUP INT TERM
ip link set lo up
ip addr show lo | grep -q '127.0.0.1/8' || ip addr add 127.0.0.1/8 dev lo
ip -f inet6 addr show lo | grep -q '::1/128' || ip -f inet6 addr add ::1/128 dev lo
stage=setup
mkdir /tmp/xkeenwrt-awg-home
/usr/libexec/xkeenwrt-integration/awg-peer config > /tmp/xkeenwrt-awg-home/config.yaml
printf '\nexternal-controller: 127.0.0.1:9090\n' >> /tmp/xkeenwrt-awg-home/config.yaml
echo LAB_AWG_STEP=config
stage=peer
/usr/libexec/xkeenwrt-integration/awg-peer peer > /tmp/xkeenwrt-awg-peer.log 2>&1 &
peer=$!
for n in 1 2 3 4 5 6 7 8 9 10; do
  grep -qx AWG_PEER_READY /tmp/xkeenwrt-awg-peer.log && break
  kill -0 "$peer" 2>/dev/null || exit 1
  sleep 1
done
grep -qx AWG_PEER_READY /tmp/xkeenwrt-awg-peer.log
echo LAB_AWG_STEP=peerready
stage=core
/usr/libexec/xkeenwrt/mihomo -d /tmp/xkeenwrt-awg-home -f /tmp/xkeenwrt-awg-home/config.yaml > /tmp/xkeenwrt-awg-core.log 2>&1 &
core=$!
stage=coreready
for n in 1 2 3 4 5 6 7 8 9 10; do
  grep -q '0100007F:1ED2 .* 0A ' /proc/net/tcp && break
  kill -0 "$core" 2>/dev/null || exit 1
  sleep 1
done
grep -q '0100007F:1ED2 .* 0A ' /proc/net/tcp
echo LAB_AWG_STEP=coreready
stage=version
wget -q -O /tmp/xkeenwrt-awg-version.json --timeout=3 --no-proxy http://127.0.0.1:9090/version
version=$(jsonfilter -i /tmp/xkeenwrt-awg-version.json -e '@.version')
case "$version" in v1.19.34|1.19.34) printf 'LAB_CORE_VERSION=%s\n' "$version";; *) exit 1;; esac
stage=client
if /usr/libexec/xkeenwrt-integration/awg-peer client > /tmp/xkeenwrt-awg-client.log 2>&1; then
  grep -qx AWG_DATA_PASS /tmp/xkeenwrt-awg-client.log
else
  for code in DIAL GREETING CONNECT ADDRESS WRITE ECHO ACK; do
    if grep -qx "AWG_FAILED_$code" /tmp/xkeenwrt-awg-client.log; then printf 'LAB_AWG_CLIENT_STATUS=%s\n' "$code"; fi
  done
  exit 1
fi
echo LAB_AWG_STEP=clientdone
stage=handshake
for n in 1 2 3 4 5 6 7 8 9 10; do
  grep -qx AWG_HANDSHAKE_AND_DATA_PASS /tmp/xkeenwrt-awg-peer.log && break
  kill -0 "$peer" 2>/dev/null || break
  sleep 1
done
grep -qx AWG_HANDSHAKE_AND_DATA_PASS /tmp/xkeenwrt-awg-peer.log
wait "$peer"
peer=
echo LAB_AWG_STEP=handshake
stage=cleanup
stop_child "$core"
core=
[ "$(cat /proc/1/comm)" = procd ]
ubus call system board >/dev/null
[ "$(for i in /sys/class/net/*; do printf '%s' "${i##*/}"; done)" = lo ]
printf 'LAB_AWG_PASS=handshake,data,cleanup\n'
trap - EXIT HUP INT TERM
