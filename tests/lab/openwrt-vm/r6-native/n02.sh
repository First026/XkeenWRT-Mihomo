#!/bin/sh
# Native manual Apply path in the isolated OpenWrt VM; relies on a preceding N01 install.
set -eu
trap 'rc=$?; echo R6_NATIVE_N02_EXIT_RC=$rc LINE=${LINENO:-unknown}; for f in /tmp/r6-peer-dnsmasq.log /tmp/r6-n02-dns-peer.txt /tmp/r6-n02-dns-before.txt /tmp/r6-n02-dhcp-preflight.json; do if [ -f "$f" ]; then echo "R6_NATIVE_N02_DIAG_FILE=$f"; cat "$f"; fi; done' EXIT
ROOT=/etc/xkeenwrt
ip=/sbin/ip
[ "$(id -u)" = 0 ]
[ "$(cat /etc/xkeenwrt-r6-native-overlay)" = r6-native-overlay-v1 ]

# Build an entirely guest-local management segment and a provider/proxy peer.
# Re-running the focused scenario in the same guest first tears down only its named fixtures.
if [ -s /tmp/r6-peer-httpd.pid ]; then kill "$(cat /tmp/r6-peer-httpd.pid)" 2>/dev/null || :; fi
rm -f /tmp/r6-peer-httpd.pid
/etc/init.d/network stop 2>/dev/null || :
/sbin/ip route del 93.184.216.34/32 via 10.0.0.3 dev wan-host 2>/dev/null || :
/sbin/ip route del 93.184.216.34/32 dev br-lan 2>/dev/null || :
for ns in xk-mgmt xk-selected xk-unselected xk-peer; do ip netns del "$ns" 2>/dev/null || :; done
for dev in eth0 eth1 eth2 wan-host; do ip link del "$dev" 2>/dev/null || :; done
uci set network.lan.ipaddr='192.168.5.1'
uci set network.lan.netmask='255.255.255.0'
uci delete network.lan.ip6assign 2>/dev/null || :
uci delete network.@device[0].ports 2>/dev/null || :
uci add_list network.@device[0].ports='eth0'
uci add_list network.@device[0].ports='eth1'
uci add_list network.@device[0].ports='eth2'
uci -q delete network.wan 2>/dev/null || :
uci set network.wan='interface'
uci set network.wan.device='wan-host'
uci set network.wan.proto='static'
uci set network.wan.ipaddr='10.0.0.1'
uci set network.wan.netmask='255.255.255.0'
uci commit network
for ns in xk-mgmt xk-selected xk-unselected xk-peer; do ip netns add "$ns"; done
make_lan_veth() {
  host=$1 peer=$2 ns=$3 mac=$4 address=$5
  ip link add "$host" type veth peer name "$peer"
  ip link set "$peer" address "$mac"
  ip link set "$host" up
  ip link set "$peer" netns "$ns"
  ip netns exec "$ns" "$ip" link set lo up
  ip netns exec "$ns" "$ip" link set "$peer" up
  ip netns exec "$ns" "$ip" addr add "$address" dev "$peer"
}
make_lan_veth eth0 mgmt0 xk-mgmt 02:00:00:00:00:02 192.168.5.2/24
make_lan_veth eth1 selected0 xk-selected 02:00:00:00:00:0a 192.168.5.10/24
make_lan_veth eth2 unselected0 xk-unselected 02:00:00:00:00:0b 192.168.5.11/24
ip link add wan-host type veth peer name peer0
ip link set wan-host up
ip link set peer0 netns xk-peer
ip netns exec xk-peer "$ip" link set lo up
ip netns exec xk-peer "$ip" addr add 10.0.0.3/24 dev peer0
ip netns exec xk-peer "$ip" addr add 93.184.216.34/32 dev peer0
ip netns exec xk-peer "$ip" link set peer0 up
ip netns exec xk-peer "$ip" route replace default via 10.0.0.1 dev peer0
/etc/init.d/network start
sleep 3
/etc/init.d/firewall reload
sleep 1
ip route add 93.184.216.34/32 via 10.0.0.3 dev wan-host
ip netns exec xk-selected "$ip" route replace default via 192.168.5.1
ubus call network.interface.wan status > /tmp/r6-n02-wan-status.json
grep -q '"up": true' /tmp/r6-n02-wan-status.json
grep -q '"l3_device": "wan-host"' /tmp/r6-n02-wan-status.json
ip -j route get 93.184.216.34 > /tmp/r6-n02-target-route.json
cat /tmp/r6-n02-target-route.json
grep -q '"gateway":"10.0.0.3"' /tmp/r6-n02-target-route.json
grep -q '"dev":"wan-host"' /tmp/r6-n02-target-route.json
echo R6_NATIVE_TARGET_EGRESS_ROUTE=WAN_10.0.0.3
ubus call network.interface.lan status > /tmp/r6-n02-lan-status.json
cat /tmp/r6-n02-lan-status.json | grep -q '"up": true'
cat /tmp/r6-n02-lan-status.json | grep -q '"l3_device": "br-lan"'

# Capture the guest's real DNS/procd state, then give this isolated fixture an
# actual dnsmasq upstream on the peer. No loopback proxy chain is fabricated.
echo R6_NATIVE_N02_STEP=dns-preflight
ubus call uci get '{"config":"dhcp"}' > /tmp/r6-n02-dhcp-before.json 2>&1 || :
ubus call uci get '{"config":"https-dns-proxy"}' > /tmp/r6-n02-https-dns-proxy-before.json 2>&1 || :
ubus call service list '{"name":"https-dns-proxy"}' > /tmp/r6-n02-https-dns-proxy-service-before.json 2>&1 || :
echo R6_NATIVE_DNS_ORIGINAL_CONFIG_BEGIN
cat /tmp/r6-n02-dhcp-before.json /tmp/r6-n02-https-dns-proxy-before.json /tmp/r6-n02-https-dns-proxy-service-before.json
echo R6_NATIVE_DNS_ORIGINAL_CONFIG_END
ip netns exec xk-peer /usr/sbin/dnsmasq --no-daemon --no-resolv --no-hosts --bind-interfaces \
  --interface=peer0 --listen-address=10.0.0.3 --port=53 \
  --log-queries --address=/r6.example.com/93.184.216.34 >/tmp/r6-peer-dnsmasq.log 2>&1 &
peer_dns_pid=$!
echo "$peer_dns_pid" > /tmp/r6-peer-dnsmasq.pid
sleep 1
if ! kill -0 "$peer_dns_pid"; then
  echo R6_NATIVE_DNS_PEER_START=FAIL
  cat /tmp/r6-peer-dnsmasq.log
  exit 1
fi
echo R6_NATIVE_DNS_PEER_START=PASS
command -v nslookup
ip netns exec xk-selected nslookup -type=A r6.example.com 10.0.0.3 > /tmp/r6-n02-dns-peer.txt 2>&1
cat /tmp/r6-n02-dns-peer.txt
grep -q '93.184.216.34' /tmp/r6-n02-dns-peer.txt
echo R6_NATIVE_DNS_PEER_QUERY=PASS
uci set dhcp.@dnsmasq[0].noresolv='1'
uci delete dhcp.@dnsmasq[0].resolvfile 2>/dev/null || :
uci set dhcp.@dnsmasq[0].local='/lan/'
uci set dhcp.@dnsmasq[0].domain='lan'
uci -q delete dhcp.@dnsmasq[0].server || :
uci add_list dhcp.@dnsmasq[0].server='10.0.0.3#53'
uci -q delete dhcp.xkeenwrt_mgmt 2>/dev/null || :
uci set dhcp.xkeenwrt_mgmt='host'
uci set dhcp.xkeenwrt_mgmt.name='native-management'
uci add_list dhcp.xkeenwrt_mgmt.mac='02:00:00:00:00:02'
uci set dhcp.xkeenwrt_mgmt.ip='192.168.5.2'
uci -q delete dhcp.xkeenwrt_selected 2>/dev/null || :
uci set dhcp.xkeenwrt_selected='host'
uci set dhcp.xkeenwrt_selected.name='native-selected'
uci add_list dhcp.xkeenwrt_selected.mac='02:00:00:00:00:0a'
uci set dhcp.xkeenwrt_selected.ip='192.168.5.10'
uci commit dhcp
echo R6_NATIVE_DNS_ROUTER_CONFIGURED
/etc/init.d/dnsmasq restart
sleep 1
echo R6_NATIVE_DNS_ROUTER_RESTARTED
ip netns exec xk-mgmt "$ip" addr flush dev mgmt0
ip netns exec xk-selected "$ip" addr flush dev selected0
ip netns exec xk-mgmt udhcpc -i mgmt0 -n -q -f -t 5 -T 1
ip netns exec xk-selected udhcpc -i selected0 -n -q -f -t 5 -T 1
awk '$2 == "02:00:00:00:00:02" && $3 == "192.168.5.2" { found=1 } END { exit !found }' /tmp/dhcp.leases
awk '$2 == "02:00:00:00:00:0a" && $3 == "192.168.5.10" { found=1 } END { exit !found }' /tmp/dhcp.leases
echo R6_NATIVE_DHCP_REAL_UDHCPC_LEASES=PASS
if ! ip netns exec xk-selected nslookup -type=A r6.example.com 192.168.5.1 > /tmp/r6-n02-dns-before.txt 2>&1; then
  echo R6_NATIVE_DNS_PREFLIGHT_QUERY=FAIL
  cat /tmp/r6-n02-dns-before.txt /tmp/r6-peer-dnsmasq.log
  ubus call uci get '{"config":"dhcp"}'
  ip addr show br-lan
  ip netns exec xk-peer ip addr show peer0
  cat /proc/net/udp
  exit 1
fi
cat /tmp/r6-n02-dns-before.txt
grep -q '93.184.216.34' /tmp/r6-n02-dns-before.txt
echo R6_NATIVE_DNS_PREFLIGHT_QUERY=PASS

mkdir -p /srv/r6-native
printf 'R6_NATIVE_TARGET_HTTP\n' > /srv/r6-native/index.txt
mkdir -p /srv/r6-native/cgi-bin
cat > /srv/r6-native/cgi-bin/hold <<'CGI'
#!/bin/sh
printf 'Content-Type: text/plain\r\n\r\n'
i=0
while [ "$i" -lt 15 ]; do
  printf 'R6_NATIVE_STREAMING\n'
  sleep 1
  i=$((i + 1))
done
CGI
chmod 755 /srv/r6-native/cgi-bin/hold
ip netns exec xk-peer /usr/sbin/uhttpd -f -h /srv/r6-native -p 0.0.0.0:80 -c /cgi-bin -n 2 -N 20 -k 1 -T 30 >/tmp/r6-peer-httpd.log 2>&1 &
echo $! > /tmp/r6-peer-httpd.pid
sleep 1

mkdir -p "$ROOT"
chmod 700 "$ROOT"
umask 077
mkdir -p /sys/fs/cgroup/xkeenwrt-validation /sys/fs/cgroup/xkeenwrt/core
[ -f /sys/fs/cgroup/xkeenwrt/core/cgroup.procs ] && [ -f /sys/fs/cgroup/xkeenwrt/core/cgroup.kill ]
printf '+memory +pids' > /sys/fs/cgroup/cgroup.subtree_control
printf '+memory +pids' > /sys/fs/cgroup/xkeenwrt-validation/cgroup.subtree_control
printf '192.168.5.1\n' > "$ROOT/management-address"
chmod 600 "$ROOT/management-address"
printf 'xkeenwrt-runtime-v1\n' > "$ROOT/runtime-enabled"
printf 'xkeenwrt-validation-v1\n' > /etc/xkeenwrt-validator-enabled
printf 'xkeenwrt-recovery-v1\n' > "$ROOT/recovery-enabled"
chmod 600 "$ROOT/runtime-enabled" /etc/xkeenwrt-validator-enabled "$ROOT/recovery-enabled"
/etc/init.d/xkeenwrt-runtime start
sleep 2
[ -s "$ROOT/owner-id" ]
/etc/init.d/xkeenwrt-ui start
sleep 2

request() {
  method=$1 path=$2 data=${3-} cookie=${4-}
  deadline=${5:-30}
  length=$(printf '%s' "$data" | wc -c | tr -d ' ')
  {
    printf '%s %s HTTP/1.1\r\n' "$method" "$path"
    printf 'Host: 192.168.5.1:1000\r\nOrigin: http://192.168.5.1:1000\r\nConnection: close\r\n'
    [ -z "$cookie" ] || printf 'Cookie: %s\r\n' "$cookie"
    printf 'Content-Type: application/json\r\nContent-Length: %s\r\n\r\n' "$length"
    printf '%s' "$data"
  } > /tmp/r6-native-request
  rm -f /tmp/r6-native-response
  ip netns exec xk-mgmt /usr/libexec/xkeenwrt-r6-native/http-wire 192.168.5.1:1000 "$deadline" >&2 || return $?
  cat /tmp/r6-native-response
}
body_of() { sed '1,/^\r*$/d' | tr -d '\r'; }
field() { sed -n "s/.*\"$1\":\"\([^\"]*\)\".*/\1/p" | head -n 1; }
check_ok() {
  response=$1 label=$2
  http=$(printf '%s\n' "$response" | tr -d '\r' | head -n 1)
  body=$(printf '%s\n' "$response" | body_of)
  code=$(printf '%s\n' "$body" | field code)
  printf 'R6_NATIVE_N02_%s_HTTP=%s\n' "$label" "${http:-MISSING}"
  printf 'R6_NATIVE_N02_%s_CODE=%s\n' "$label" "${code:-NONE}"
  printf '%s\n' "$http" | grep -q '^HTTP/1.1 200' || { echo "R6_NATIVE_N02_${label}=HTTP_FAIL"; printf '%s\n' "$response"; return 1; }
  if [ "$label" = core_relay ]; then
    printf '%s\n' "$body" | grep -q '"version":"v1.19.34"' || { echo "R6_NATIVE_N02_${label}=VERSION_FAIL"; printf '%s\n' "$response"; return 1; }
  else
    printf '%s\n' "$body" | grep -q '"success":true' || { echo "R6_NATIVE_N02_${label}=API_FAIL"; printf '%s\n' "$response"; return 1; }
  fi
}
echo R6_NATIVE_N02_STEP=auth-login-info
login_info=$(request GET /api/auth/login)
login_http=$(printf '%s\n' "$login_info" | tr -d '\r' | head -n 1)
echo "R6_NATIVE_N02_LOGIN_HTTP=${login_http:-MISSING}"
printf '%s\n' "$login_http" | grep -q '^HTTP/1.1 200' || { printf '%s\n' "$login_info"; exit 1; }
token=$(cat "$ROOT/bootstrap-token")
password=NativeR6SyntheticPass2026
echo R6_NATIVE_N02_STEP=auth-setup
setup_response=$(request POST /api/auth/setup "{\"password\":\"$password\",\"token\":\"$token\"}" '' 60)
check_ok "$setup_response" setup
cookie=$(printf '%s\n' "$setup_response" | tr -d '\r' | sed -n 's/^[Ss]et-[Cc]ookie: \(session_id=[^;]*\).*/\1/p' | head -n 1)
[ -n "$cookie" ]
printf '%s\n' "$cookie" > /tmp/r6-native-session-cookie
echo R6_NATIVE_N02_STEP=platform-status
platform=$(request GET /api/platform '' "$cookie")
platform_http=$(printf '%s\n' "$platform" | tr -d '\r' | head -n 1)
platform_body=$(printf '%s\n' "$platform" | body_of)
platform_code=$(printf '%s\n' "$platform_body" | field code)
echo "R6_NATIVE_N02_platform_HTTP=${platform_http:-MISSING}"
echo "R6_NATIVE_N02_platform_CODE=${platform_code:-NONE}"
printf '%s\n' "$platform_body" | grep -q '"profile_validate"'
printf '%s\n' "$platform_body" | grep -q '"profile_apply_manual"'
echo R6_NATIVE_N02_STEP=runtime-status
control=$(request GET /api/control '' "$cookie")
check_ok "$control" control

# JSON escapes encode the preserved YAML source; all data and endpoints are synthetic.
source='mixed-port: 7890\nmode: rule\nlog-level: info\nrules:\n  - MATCH,DIRECT\n'
echo R6_NATIVE_N02_STEP=profile-import
put=$(request PUT /api/profiles/native "{\"source\":\"$source\",\"expected_revision\":null}" "$cookie")
check_ok "$put" profile_save
revision=$(printf '%s\n' "$put" | body_of | field revision)
[ -n "$revision" ]
echo R6_NATIVE_N02_STEP=prepare
prepare=$(request POST /api/profiles/native/prepare "{\"expected_revision\":\"$revision\"}" "$cookie")
check_ok "$prepare" prepare
printf '%s\n' "$prepare" | body_of | grep -q 'manual-preview'
echo R6_NATIVE_N02_STEP=validate
validate=$(request POST /api/profiles/native/validate "{\"expected_revision\":\"$revision\"}" "$cookie")
check_ok "$validate" validate
candidate=$(printf '%s\n' "$validate" | body_of | field candidate_id)
[ -n "$candidate" ]
printf '%s\n' "$validate" | body_of | grep -q '"status":"valid"'

# Snapshot foreign network and DNS state immediately before manual activation.
mkdir -p /tmp/r6-n02-baseline
nft -j list ruleset > /tmp/r6-n02-baseline/nft.json
ip -j rule show > /tmp/r6-n02-baseline/rules.json
ip -j route show table all > /tmp/r6-n02-baseline/routes.json
cp /etc/config/network /tmp/r6-n02-baseline/network
cp /etc/config/dhcp /tmp/r6-n02-baseline/dhcp
echo R6_NATIVE_N02_STEP=manual-apply
echo R6_NATIVE_N02_APPLY_MEMINFO=$(awk '/^MemAvailable:/{print $2 " " $3}' /proc/meminfo)
df -Pk /tmp /etc/xkeenwrt | sed 's/^/R6_NATIVE_N02_APPLY_DF=/'
apply=$(request POST /api/profiles/native/apply "{\"expected_revision\":\"$revision\",\"candidate_id\":\"$candidate\",\"idempotency_key\":\"n02-manual-apply\"}" "$cookie")
if ! check_ok "$apply" apply; then
  echo R6_NATIVE_N02_APPLY_DIAGNOSTICS_BEGIN
  cat /usr/share/xkeenwrt/ui-manifest.json
  sha256sum /usr/bin/xkeenwrt-ui /usr/libexec/xkeenwrt/xkeenwrt-validate /usr/libexec/xkeenwrt/xkeenwrt-recovery /usr/libexec/xkeenwrt/mihomo
  ls -l /etc/init.d/xkeenwrt-* /etc/rc.d/*xkeenwrt* 2>&1 || :
  for service in xkeenwrt-runtime xkeenwrt-ui xkeenwrt-core xkeenwrt-rescue xkeenwrt-recovery; do
    echo "R6_NATIVE_APPLY_SERVICE=$service"
    ubus call service list "{\"name\":\"$service\"}" 2>&1 || :
  done
  echo "R6_NATIVE_APPLY_CORE_CGROUP=$(cat /sys/fs/cgroup/xkeenwrt/core/cgroup.controllers 2>&1)"
  echo "R6_NATIVE_APPLY_CORE_LIMITS=$(cat /sys/fs/cgroup/xkeenwrt/core/memory.max /sys/fs/cgroup/xkeenwrt/core/memory.swap.max /sys/fs/cgroup/xkeenwrt/core/pids.max /sys/fs/cgroup/xkeenwrt/core/memory.oom.group 2>&1 | tr '\n' ',')"
  echo R6_NATIVE_N02_APPLY_DIAGNOSTICS_END
  exit 1
fi
transaction=$(printf '%s\n' "$apply" | body_of | field id)
[ -n "$transaction" ]
/etc/init.d/xkeenwrt-rescue start
sleep 2
rescue_service=$(ubus call service list '{"name":"xkeenwrt-rescue"}')
printf '%s\n' "$rescue_service" | grep -q '"running": true'
echo R6_NATIVE_N02_STEP=rescue-dns-preflight
printf '%s\n' "$rescue_service"
ls -l /etc/init.d/xkeenwrt-rescue /etc/rc.d/S* xkeenwrt-rescue 2>/dev/null | grep xkeenwrt-rescue || :
ubus call uci get '{"config":"dhcp"}' > /tmp/r6-n02-dhcp-preflight.json
ubus call uci get '{"config":"https-dns-proxy"}' > /tmp/r6-n02-proxy-preflight.json 2>&1 || :
ubus call service list '{"name":"https-dns-proxy"}' > /tmp/r6-n02-proxy-service-preflight.json 2>&1 || :
echo R6_NATIVE_DNS_CHAIN_BEGIN
cat /tmp/r6-n02-dhcp-preflight.json /tmp/r6-n02-proxy-preflight.json /tmp/r6-n02-proxy-service-preflight.json
echo R6_NATIVE_DNS_CHAIN_END

echo R6_NATIVE_N02_STEP=core-start
start=$(request POST /api/control '{"action":"start"}' "$cookie")
check_ok "$start" start
echo R6_NATIVE_N02_STEP=core-status
status=$(request GET /api/control '' "$cookie")
check_ok "$status" status
printf '%s\n' "$status" | body_of | grep -q '"running":true'
echo R6_NATIVE_N02_STEP=core-relay
relay=$(request GET /api/core/version '' "$cookie")
check_ok "$relay" core_relay
echo R6_NATIVE_MANUAL_CORE=PASS
echo R6_NATIVE_N02_STEP=network-plan
prepare_network=$(request POST /api/profiles/native/prepare "{\"expected_revision\":\"$revision\"}" "$cookie")
check_ok "$prepare_network" prepare_network
validate_network=$(request POST /api/profiles/native/validate "{\"expected_revision\":\"$revision\"}" "$cookie")
check_ok "$validate_network" validate_network
network_candidate=$(printf '%s\n' "$validate_network" | body_of | field candidate_id)
[ -n "$network_candidate" ]
network_plan=$(request POST /api/network/plan "{\"profile_id\":\"native\",\"expected_revision\":\"$revision\",\"candidate_id\":\"$network_candidate\",\"lan_interface\":\"br-lan\",\"selected_ipv4\":\"192.168.5.10\",\"management_ipv4\":\"192.168.5.2\",\"selected_ipv6\":[],\"management_ipv6\":[],\"ipv6_policy\":\"block_external\",\"failure_policy\":\"direct_on_failure\"}" "$cookie")
check_ok "$network_plan" network_plan
network_plan_body=$(printf '%s\n' "$network_plan" | body_of)
network_plan_failure_policy=$(printf '%s\n' "$network_plan_body" | sed -n 's/.*"failure_policy":"\([^"]*\)".*/\1/p' | head -n 1)
echo "R6_NATIVE_PLAN_FAILURE_POLICY=${network_plan_failure_policy:-UNREPORTED}"
network_plan_local_ipv4=$(grep -o '"local_ipv4":\[[^]]*\]' "$ROOT/network-plan.json" | head -n 1)
if [ -n "$network_plan_local_ipv4" ]; then
  printf 'R6_NATIVE_PLAN_LOCAL_IPV4=%s\n' "$network_plan_local_ipv4"
  if printf '%s\n' "$network_plan_local_ipv4" | grep -q '93.184.216.34'; then
    echo R6_NATIVE_PLAN_TARGET_IN_LOCAL_IPV4=YES
  else
    echo R6_NATIVE_PLAN_TARGET_IN_LOCAL_IPV4=NO
  fi
else
  echo R6_NATIVE_PLAN_LOCAL_IPV4=UNREPORTED
fi

# Preserve both actual pre-Apply input passes in the bounded serial log so the
# existing host capture_fixed parser can replay the failure without rebuilding.
capture_network_inputs() {
  label=$1 dir="/tmp/r7-capture-$1"
  mkdir -p "$dir"
  cp "$ROOT/network-plan.json" "$dir/network-plan.json"
  cp /tmp/dhcp.leases "$dir/leases"
  ip -j link show > "$dir/links"
  ip -j address show > "$dir/addresses"
  ip -j neigh show > "$dir/neighbours"
  ubus call network.interface dump > "$dir/netifd"
  ubus call uci get '{"config":"dhcp"}' > "$dir/dnsconfig"
  : > "$dir/proxyconfig"
  : > "$dir/proxyservice"
  nft -j list ruleset > "$dir/nft"
  ip -j -4 rule show > "$dir/rules4"
  ip -j -6 rule show > "$dir/rules6"
  ip -j -4 route show table all > "$dir/routes4"
  ip -j -6 route show table all > "$dir/routes6"
  cat /proc/net/tcp > "$dir/tcp4"
  cat /proc/net/udp > "$dir/udp4"
  cat /proc/net/tcp6 > "$dir/tcp6"
  cat /proc/net/udp6 > "$dir/udp6"
  total=0
  for file in network-plan.json leases links addresses neighbours netifd dnsconfig proxyconfig proxyservice nft rules4 rules6 routes4 routes6 tcp4 udp4 tcp6 udp6; do
    size=$(wc -c < "$dir/$file" | tr -d ' ')
    [ "$size" -le 262144 ] || { echo "R7_CAPTURE_${label}_OVERSIZE=$file:$size"; return 1; }
    total=$((total + size))
  done
  [ "$total" -le 1048576 ] || { echo "R7_CAPTURE_${label}_TOTAL_OVERSIZE=$total"; return 1; }
  echo "R7_CAPTURE_${label}_TOTAL_BYTES=$total"
  for file in network-plan.json leases links addresses neighbours netifd dnsconfig proxyconfig proxyservice nft rules4 rules6 routes4 routes6 tcp4 udp4 tcp6 udp6; do
    echo "R7_CAPTURE_${label}_${file}_BEGIN"
    cat "$dir/$file"
    echo "R7_CAPTURE_${label}_${file}_END"
  done
}
echo R6_NATIVE_N02_STEP=pre-apply-evidence
capture_network_inputs A
capture_network_inputs B
plan_id=$(printf '%s\n' "$network_plan" | body_of | field plan_id)
[ -n "$plan_id" ]
echo R6_NATIVE_N02_STEP=network-apply
network_apply=$(request POST /api/network/apply "{\"plan_id\":\"$plan_id\",\"idempotency_key\":\"n02-network-apply\"}" "$cookie")
check_ok "$network_apply" network_apply
transaction_id=$(printf '%s\n' "$network_apply" | body_of | field transaction_id)
confirm_token=$(printf '%s\n' "$network_apply" | body_of | field confirm_token)
[ -n "$transaction_id" ] && [ -n "$confirm_token" ]
echo R6_NATIVE_N02_STEP=network-confirm
confirm=$(request POST /api/network/confirm "{\"transaction_id\":\"$transaction_id\",\"confirm_token\":\"$confirm_token\"}" "$cookie")
check_ok "$confirm" network_confirm
echo R6_NATIVE_N02_STEP=network-status
network_status=$(request GET /api/network/status '' "$cookie")
check_ok "$network_status" network_status
printf '%s\n' "$network_status" | body_of | grep -q '"state":"active"'
echo R6_NATIVE_N02_STEP=selected-dns-through-network
ip netns exec xk-selected nslookup -type=A r6.example.com 192.168.5.1 > /tmp/r6-n02-dns-active.txt 2>&1
cat /tmp/r6-n02-dns-active.txt
grep -q '93.184.216.34' /tmp/r6-n02-dns-active.txt
echo R6_NATIVE_N02_STEP=selected-http-through-network
printf 'GET /cgi-bin/hold HTTP/1.1\r\nHost: r6.example.com\r\nConnection: close\r\n\r\n' > /tmp/r6-native-request
rm -f /tmp/r6-native-response
ip netns exec xk-selected /usr/libexec/xkeenwrt-r6-native/http-wire 93.184.216.34:80 30 >/tmp/r6-n02-selected-http.log 2>&1 &
selected_http_pid=$!
sleep 2
connections=$(request GET /api/core/connections '' "$cookie")
connections_http=$(printf '%s\n' "$connections" | tr -d '\r' | head -n 1)
connections_body=$(printf '%s\n' "$connections" | body_of)
echo "R6_NATIVE_N02_connections_HTTP=${connections_http:-MISSING}"
printf '%s\n' "$connections_body" | grep -q '"sourceIP":"192.168.5.10"'
printf '%s\n' "$connections_body" | grep -q '"destinationIP":"93.184.216.34"'
echo R6_NATIVE_MIHOMO_CONNECTION=SELECTED_CLIENT_TO_93.184.216.34
wait "$selected_http_pid"
cat /tmp/r6-n02-selected-http.log
grep -q 'R6_NATIVE_STREAMING' /tmp/r6-native-response
echo R6_NATIVE_N02_STEP=network-disable
disable=$(request POST /api/network/disable '{"idempotency_key":"n02-network-disable"}' "$cookie")
check_ok "$disable" network_disable
disable_status=
attempt=0
while [ "$attempt" -lt 30 ]; do
  disable_status=$(request GET /api/network/status '' "$cookie")
  disable_http=$(printf '%s\n' "$disable_status" | tr -d '\r' | head -n 1)
  disable_body=$(printf '%s\n' "$disable_status" | body_of)
  if [ "$disable_http" = 'HTTP/1.1 503 Service Unavailable' ] \
    && printf '%s\n' "$disable_body" | grep -q '"code":"BUSY"'; then
    sleep 1
    attempt=$((attempt + 1))
    continue
  fi
  check_ok "$disable_status" network_disable_status
  if printf '%s\n' "$disable_body" | grep -q '"outcome":"disabled","state":"completed"'; then
    break
  fi
  sleep 1
  attempt=$((attempt + 1))
done
printf '%s\n' "$disable_body" | grep -q '"outcome":"disabled","state":"completed"' || {
  echo R6_NATIVE_NETWORK_DISABLE=COMPLETION_TIMEOUT
  printf '%s\n' "$disable_status"
  exit 1
}
nft list table inet xkeenwrt >/dev/null 2>&1 && { echo R6_NATIVE_NETWORK_DISABLE=OWN_TABLE_REMAINS; exit 1; }
nft list table inet fw4 >/dev/null
ip -j rule show > /tmp/r6-n02-after-rules.json
ip -j route show table all > /tmp/r6-n02-after-routes.json
cmp /tmp/r6-n02-baseline/rules.json /tmp/r6-n02-after-rules.json
cmp /tmp/r6-n02-baseline/routes.json /tmp/r6-n02-after-routes.json
cmp /tmp/r6-n02-baseline/network /etc/config/network
cmp /tmp/r6-n02-baseline/dhcp /etc/config/dhcp
echo R6_NATIVE_N02_STEP=disabled-direct-http-and-dns
printf 'GET /index.txt HTTP/1.1\r\nHost: r6.example.com\r\nConnection: close\r\n\r\n' > /tmp/r6-native-request
rm -f /tmp/r6-native-response
ip netns exec xk-selected /usr/libexec/xkeenwrt-r6-native/http-wire 93.184.216.34:80 8 >&2
grep -q 'R6_NATIVE_TARGET_HTTP' /tmp/r6-native-response
ip netns exec xk-selected nslookup -type=A r6.example.com 192.168.5.1 > /tmp/r6-n02-dns-disabled.txt 2>&1
grep -q '93.184.216.34' /tmp/r6-n02-dns-disabled.txt

# Reapply the same explicit direct-on-failure plan, then let persistent rescue
# observe an actual killed Mihomo process and withdraw only its owned capture.
echo R6_NATIVE_N02_STEP=network-reapply-for-core-failure
prepare2=$(request POST /api/profiles/native/prepare "{\"expected_revision\":\"$revision\"}" "$cookie")
check_ok "$prepare2" prepare_again
validate2=$(request POST /api/profiles/native/validate "{\"expected_revision\":\"$revision\"}" "$cookie")
check_ok "$validate2" validate_again
candidate2=$(printf '%s\n' "$validate2" | body_of | field candidate_id)
[ -n "$candidate2" ]
plan2=$(request POST /api/network/plan "{\"profile_id\":\"native\",\"expected_revision\":\"$revision\",\"candidate_id\":\"$candidate2\",\"lan_interface\":\"br-lan\",\"selected_ipv4\":\"192.168.5.10\",\"management_ipv4\":\"192.168.5.2\",\"selected_ipv6\":[],\"management_ipv6\":[],\"ipv6_policy\":\"block_external\",\"failure_policy\":\"direct_on_failure\"}" "$cookie")
check_ok "$plan2" network_plan_again
plan_id2=$(printf '%s\n' "$plan2" | body_of | field plan_id)
[ -n "$plan_id2" ]
apply2=$(request POST /api/network/apply "{\"plan_id\":\"$plan_id2\",\"idempotency_key\":\"n02-network-core-failure\"}" "$cookie")
check_ok "$apply2" network_apply_again
transaction_id2=$(printf '%s\n' "$apply2" | body_of | field transaction_id)
confirm_token2=$(printf '%s\n' "$apply2" | body_of | field confirm_token)
[ -n "$transaction_id2" ] && [ -n "$confirm_token2" ]
confirm2=$(request POST /api/network/confirm "{\"transaction_id\":\"$transaction_id2\",\"confirm_token\":\"$confirm_token2\"}" "$cookie")
check_ok "$confirm2" network_confirm_again
echo R6_NATIVE_N02_STEP=kill-mihomo-and-observe-direct-fallback
core_pid=$(pidof mihomo)
[ -n "$core_pid" ]
echo "R6_NATIVE_KILLED_MIHOMO_PID=$core_pid"
kill -KILL $core_pid
attempt=0
while nft list table inet xkeenwrt >/dev/null 2>&1 && [ "$attempt" -lt 30 ]; do
  sleep 1
  attempt=$((attempt + 1))
done
nft list table inet xkeenwrt >/dev/null 2>&1 && { echo R6_NATIVE_CORE_FAILURE_OWN_TABLE_REMAINS; exit 1; }
ip -j rule show > /tmp/r6-n02-failure-rules.json
ip -j route show table all > /tmp/r6-n02-failure-routes.json
cmp /tmp/r6-n02-baseline/rules.json /tmp/r6-n02-failure-rules.json
cmp /tmp/r6-n02-baseline/routes.json /tmp/r6-n02-failure-routes.json
printf 'GET /index.txt HTTP/1.1\r\nHost: r6.example.com\r\nConnection: close\r\n\r\n' > /tmp/r6-native-request
rm -f /tmp/r6-native-response
ip netns exec xk-selected /usr/libexec/xkeenwrt-r6-native/http-wire 93.184.216.34:80 8 >&2
grep -q 'R6_NATIVE_TARGET_HTTP' /tmp/r6-native-response
ip netns exec xk-selected nslookup -type=A r6.example.com 192.168.5.1 > /tmp/r6-n02-dns-failure.txt 2>&1
grep -q '93.184.216.34' /tmp/r6-n02-dns-failure.txt
echo R6_NATIVE_CORE_FAILURE_DIRECT_FALLBACK=PASS
echo R6_NATIVE_N02_STEP=core-stop
stop=$(request POST /api/control '{"action":"stop"}' "$cookie")
check_ok "$stop" stop
echo R6_NATIVE_N02_STEP=core-status
status=$(request GET /api/control '' "$cookie")
check_ok "$status" stopped
printf '%s\n' "$status" | body_of | grep -q '"running":false'
printf 'R6_NATIVE_N02_PROFILE=%s\n' "$revision"
printf 'R6_NATIVE_N02_CANDIDATE=%s\n' "$candidate"
printf 'R6_NATIVE_N02_TRANSACTION=%s\n' "$transaction"
printf 'R6_NATIVE_N02_NETWORK_TRANSACTION=%s\n' "$transaction_id"
echo 'R6_NATIVE_MANUAL_APPLY=PASS'
echo 'R6_NATIVE_NETWORK_APPLY_CONFIRM_DISABLE=PASS'
echo 'R6_NATIVE_SELECTED_TRAFFIC_MIHOMO=PASS'
echo 'R6_NATIVE_DIRECT_ON_CORE_FAILURE=PASS'
echo 'R6_NATIVE_FOREIGN_CONFIG_AND_ROUTES=UNCHANGED'
echo 'R6_NATIVE_N02=PASS'
