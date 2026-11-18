#!/bin/sh
# Shared helpers for the 0.1.26.2 acceptance guest. Runs only inside the disposable
# lab VM (marker /etc/xk-lab). Requests come either from the LAN management
# namespace (use_lan) or from the tailnet stand-in namespace (use_ts).
[ "$(cat /etc/xk-lab 2>/dev/null)" = xk-lab-r262-v1 ] || { echo 'XK_LAB=NOT_A_LAB_GUEST'; exit 1; }
ROOT=/etc/xkeenwrt
TS_ROUTER=100.64.10.1
use_lan() { NS=xk-mgmt; PANEL=192.168.5.1:1000; }
use_ts() { NS=xk-ts; PANEL=$TS_ROUTER:1000; }
use_lan
# Profile policy admits wireguard/vless/vmess/trojan/ss/hysteria2 only.
PROFILE='mode: rule
proxies:
  - {name: lab-ss, type: ss, server: 10.0.0.3, port: 8388, cipher: aes-128-gcm, password: lab-synthetic}
rules:
  - DOMAIN-SUFFIX,gstatic.com,lab-ss
  - MATCH,DIRECT'
api() { # api METHOD PATH [JSON] -> body on stdout, HTTP code in /tmp/xk-code
  method=$1 path=$2 body=${3:-}
  if [ -n "$body" ]; then
    ip netns exec "$NS" curl -sS -m 200 -o /tmp/xk-body -w '%{http_code}' -X "$method" \
      -H "Host: $PANEL" -H 'Content-Type: application/json' -H 'X-XkeenWRT-Status-Fresh: 1' \
      --data "$body" "http://$PANEL$path" > /tmp/xk-code || echo 000 > /tmp/xk-code
  else
    ip netns exec "$NS" curl -sS -m 200 -o /tmp/xk-body -w '%{http_code}' -X "$method" \
      -H "Host: $PANEL" -H 'X-XkeenWRT-Status-Fresh: 1' "http://$PANEL$path" > /tmp/xk-code || echo 000 > /tmp/xk-code
  fi
  cat /tmp/xk-body 2>/dev/null
}
code() { cat /tmp/xk-code; }
field() { jsonfilter -s "$1" -e "$2" 2>/dev/null; }
key() { head -c 16 /dev/urandom | hexdump -v -e '/1 "%02x"'; }
wait_api() { # until GET /api/control answers on the current channel
  n=0; while [ "$n" -lt 120 ]; do
    out=$(api GET /api/control); [ "$(code)" = 200 ] && return 0
    sleep 2; n=$((n + 1)); done
  echo "XK_LAB_API=UNREACHABLE ns=$NS $out"; return 1
}
ensure_mihomo() {
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
  [ "$(field "$cat" '@.installedVersion')" = 1.19.34 ] || { echo "XK_LAB_MIHOMO=FAIL $cat"; return 1; }
  echo XK_LAB_MIHOMO=VERIFIED
}
save_profile() { # save_profile ID YAML -> revision
  current=$(api GET "/api/profiles/$1"); rev=$(field "$current" '@.profile.revision')
  json=$(printf '%s' "$2" | sed 's/\\/\\\\/g; s/"/\\"/g' | awk 'BEGIN{ORS="\\n"}{print}')
  if [ -n "$rev" ]; then out=$(api PUT "/api/profiles/$1" "{\"source\":\"$json\",\"expected_revision\":\"$rev\"}")
  else out=$(api PUT "/api/profiles/$1" "{\"source\":\"$json\",\"expected_revision\":null}"); fi
  field "$out" '@.profile.revision'
}
confirm_pending() { # confirm_pending REPLY -> confirm reply body; like confirmNetworkIfPending
  tx=$(field "$1" '@.network.transaction_id'); token=$(field "$1" '@.network.confirm_token')
  [ -n "$tx" ] && [ -n "$token" ] || { echo "{\"lab\":\"no pending tx\"}"; return 1; }
  st=$(api GET /api/network/status)
  [ "$(field "$st" '@.network.transaction_id')" = "$tx" ] || { echo "{\"lab\":\"status tx changed\"}"; return 1; }
  api POST /api/network/confirm "{\"transaction_id\":\"$tx\",\"confirm_token\":\"$token\"}"
}
apply_profile() { # apply_profile ID REV; confirms a replacement when the gateway runs
  v=$(api POST "/api/profiles/$1/validate" "{\"expected_revision\":\"$2\"}")
  cand=$(field "$v" '@.validation.candidate_id')
  [ -n "$cand" ] || { echo "XK_LAB_VALIDATE=FAIL code=$(code) $v"; return 1; }
  a=$(api POST "/api/profiles/$1/apply" "{\"expected_revision\":\"$2\",\"candidate_id\":\"$cand\",\"idempotency_key\":\"$(key)\"}")
  [ "$(field "$a" '@.success')" = true ] || { echo "XK_LAB_APPLY=FAIL code=$(code) $a"; return 1; }
  if [ "$(field "$a" '@.network.state')" = pending ]; then
    c=$(confirm_pending "$a")
    [ "$(field "$c" '@.network.state')" = confirmed ] || { echo "XK_LAB_APPLY_CONFIRM=FAIL code=$(code) $c"; return 1; }
    echo "XK_LAB_APPLY_REPLACED_CONFIRMED channel=$NS"
  fi
  echo "XK_LAB_APPLY=PASS"
}
wait_state() { # wait_state STATE [seconds]
  n=0; while [ "$n" -lt "${2:-60}" ]; do
    c=$(api GET /api/control)
    [ "$(field "$c" '@.network.state')" = "$1" ] && return 0
    sleep 1; n=$((n + 1)); done
  echo "XK_LAB_STATE=NOT_$1 $c"; return 1
}
start_gateway() { # Start -> status -> Confirm -> active, like startLanService
  s=$(api POST /api/control '{"action":"start"}')
  state=$(field "$s" '@.network.state')
  if [ "$state" != active ]; then
    [ "$state" = pending ] || { echo "XK_LAB_START=FAIL code=$(code) $s"; return 1; }
    c=$(confirm_pending "$s")
    [ "$(field "$c" '@.network.state')" = confirmed ] || { echo "XK_LAB_CONFIRM=FAIL code=$(code) $c"; return 1; }
    LAST_CONFIRM=$c
  fi
  n=0; while [ "$n" -lt 30 ]; do
    c=$(api GET /api/control)
    [ "$(field "$c" '@.running')" = true ] && [ "$(field "$c" '@.network.state')" = active ] && { echo XK_LAB_START=PASS; return 0; }
    sleep 1; n=$((n + 1)); done
  echo "XK_LAB_START=NOT_ACTIVE $c"; return 1
}
stop_gateway() {
  n=0; while [ "$n" -lt 60 ]; do
    s=$(api POST /api/control '{"action":"stop"}'); st=$(field "$s" '@.network.state')
    [ "$st" = stopped ] && break
    sleep 1; n=$((n + 1)); done
  c=$(api GET /api/control)
  [ "$(field "$c" '@.running')" = false ] && [ "$(field "$c" '@.network.state')" = inactive ] && { echo XK_LAB_STOP=PASS; return 0; }
  echo "XK_LAB_STOP=FAIL $c"; return 1
}
lan_fetch() { # HTTPS to the lab "blocked site" from the LAN client; HTTP code or 000
  ip netns exec xk-mgmt curl -sS -m 25 -o /dev/null -w '%{http_code}' https://www.gstatic.com/generate_204 2>/dev/null || :
}
lan_fetch_direct() { # plain HTTP to the lab site the rules send DIRECT; HTTP code or 000
  ip netns exec xk-mgmt curl -sS -m 25 -o /dev/null -w '%{http_code}' http://1.2.3.5/ 2>/dev/null || :
}
own_table_absent() { ! nft list table inet xkeenwrt >/dev/null 2>&1; }
history_entries() {
  n=0; for t in history network-history active-event-history payloads; do
    [ -d "$ROOT/$t" ] && n=$((n + $(find "$ROOT/$t" -mindepth 1 | wc -l))); done; echo "$n"
}
references_intact() { # every snapshot a journal names exists
  for j in "$ROOT/recovery.json" "$ROOT"/network-history/*.json; do
    [ -f "$j" ] || continue
    keys="current_core previous_core baseline_core next_baseline_core"
    [ "$(jsonfilter -i "$j" -e '@.completion.kind' 2>/dev/null)" = rollback_direct ] && keys=current_core
    for k in $keys; do
      id=$(jsonfilter -i "$j" -e "@.$k.snapshot_id" 2>/dev/null) || continue
      [ -z "$id" ] || [ -d "$ROOT/history/$id" ] || { echo "XK_LAB_DANGLING=$j:$k:$id"; return 1; }
    done
  done
  return 0
}
no_recovery_crash() { [ "$(logread | grep -c 'recovery stopped')" = 0 ]; }
start_peer_proxy() { # Shadowsocks on 10.0.0.3:8388 and HTTPS www.gstatic.com on 1.2.3.4:443
  d=/tmp/xk-peer-mihomo; mkdir -p "$d"
  # Mihomo reads TLS files only inside its home directory.
  cp /usr/share/xk-lab/tls/server.crt /usr/share/xk-lab/tls/server.key "$d/"
  cat > "$d/config.yaml" <<'YAML'
allow-lan: true
mode: direct
listeners:
  - {name: lab-ss, type: shadowsocks, listen: 10.0.0.3, port: 8388, cipher: aes-128-gcm, password: lab-synthetic}
log-level: warning
secret: lab
external-controller-tls: 1.2.3.4:443
tls:
  certificate: /tmp/xk-peer-mihomo/server.crt
  private-key: /tmp/xk-peer-mihomo/server.key
hosts:
  'www.gstatic.com': 1.2.3.4
dns:
  enable: true
  use-hosts: true
  nameserver: [127.0.0.1]
YAML
  # A distinct executable name: the release installer treats any running
  # process named mihomo as the product's core (`pidof mihomo`).
  [ -e /usr/share/xk-lab/lab-peer ] || ln /usr/share/xk-lab/mihomo /usr/share/xk-lab/lab-peer
  ip netns exec xk-peer /usr/share/xk-lab/lab-peer -d "$d" > /tmp/xk-peer-mihomo.log 2>&1 &
  echo $! > /tmp/xk-peer-mihomo.pid
  n=0; while [ "$n" -lt 30 ]; do
    ip netns exec xk-peer curl -sS -m 3 -o /dev/null https://www.gstatic.com/ 2>/dev/null && { echo XK_LAB_PEER_PROXY=UP; return 0; }
    sleep 1; n=$((n + 1)); done
  echo "XK_LAB_PEER_PROXY=DOWN"; tail -5 /tmp/xk-peer-mihomo.log; return 1
}
stop_peer_proxy() { kill "$(cat /tmp/xk-peer-mihomo.pid)" 2>/dev/null || :; sleep 1; }
start_peer_site() { # plain HTTP site on 1.2.3.5:80, its own process: it outlives a stopped proxy
  d=/tmp/xk-peer-site; mkdir -p "$d"
  printf 'mode: direct\nlog-level: warning\nsecret: lab\nexternal-controller: 1.2.3.5:80\n' > "$d/config.yaml"
  [ -e /usr/share/xk-lab/lab-site ] || ln /usr/share/xk-lab/mihomo /usr/share/xk-lab/lab-site
  ip netns exec xk-peer /usr/share/xk-lab/lab-site -d "$d" > /tmp/xk-peer-site.log 2>&1 &
  echo $! > /tmp/xk-peer-site.pid
  n=0; while [ "$n" -lt 30 ]; do
    ip netns exec xk-peer curl -sS -m 3 -o /dev/null http://1.2.3.5/ 2>/dev/null && { echo XK_LAB_PEER_SITE=UP; return 0; }
    sleep 1; n=$((n + 1)); done
  echo XK_LAB_PEER_SITE=DOWN; tail -5 /tmp/xk-peer-site.log; return 1
}
start_peer_dns() { # upstream DNS of the router on the WAN peer
  # Local-only domains: AAAA gets an empty NOERROR instead of REFUSED (there is
  # no upstream), which musl's resolver would treat as a failed lookup.
  ip netns exec xk-peer /usr/sbin/dnsmasq --no-daemon --no-resolv --no-hosts --bind-interfaces \
    --interface=peer0 --listen-address=10.0.0.3 --port=53 --local=/lab.example/ --local=/gstatic.com/ \
    --host-record=lab.example,10.0.0.3 --host-record=www.gstatic.com,1.2.3.4 --local-ttl=60 >/tmp/xk-peer-dns.log 2>&1 &
  echo $! > /tmp/xk-peer-dns.pid
  sleep 1
}
stop_peer_dns() { kill "$(cat /tmp/xk-peer-dns.pid)" 2>/dev/null || :; sleep 1; }
restart_gateway() { # like restartManagedService: stopping -> pending/confirm or restarted
  n=0; while [ "$n" -lt 60 ]; do
    r=$(api POST /api/control '{"action":"restart"}'); st=$(field "$r" '@.network.state')
    case "$st" in
      pending)
        c=$(confirm_pending "$r")
        [ "$(field "$c" '@.network.state')" = confirmed ] || { echo "XK_LAB_RESTART_CONFIRM=FAIL code=$(code) $c"; return 1; }
        LAST_CONFIRM=$c
        wait_state active 30 && { echo XK_LAB_RESTART=PASS; return 0; }; return 1 ;;
      restarted) echo XK_LAB_RESTART=PASS; return 0 ;;
      stopping) sleep 1 ;;
      *) echo "XK_LAB_RESTART=FAIL code=$(code) $r"; return 1 ;;
    esac
    n=$((n + 1)); done
  echo XK_LAB_RESTART=TIMEOUT; return 1
}
