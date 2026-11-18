#!/bin/sh
# Shared helpers for the r26 acceptance guest. Runs only inside the disposable
# lab VM (marker /etc/xk-lab); requests come from the management netns.
[ "$(cat /etc/xk-lab 2>/dev/null)" = xk-lab-r26-v1 ] || { echo 'XK_LAB=NOT_A_LAB_GUEST'; exit 1; }
PANEL=192.168.5.1:1000
ROOT=/etc/xkeenwrt
api() { # api METHOD PATH [JSON] -> body on stdout, HTTP code in /tmp/xk-code
  method=$1 path=$2 body=${3:-}
  if [ -n "$body" ]; then
    ip netns exec xk-mgmt curl -sS -m 200 -o /tmp/xk-body -w '%{http_code}' -X "$method" \
      -H "Host: $PANEL" -H 'Content-Type: application/json' -H 'X-XkeenWRT-Status-Fresh: 1' \
      --data "$body" "http://$PANEL$path" > /tmp/xk-code || echo 000 > /tmp/xk-code
  else
    ip netns exec xk-mgmt curl -sS -m 200 -o /tmp/xk-body -w '%{http_code}' -X "$method" \
      -H "Host: $PANEL" -H 'X-XkeenWRT-Status-Fresh: 1' "http://$PANEL$path" > /tmp/xk-code || echo 000 > /tmp/xk-code
  fi
  cat /tmp/xk-body 2>/dev/null
}
field() { jsonfilter -s "$1" -e "$2" 2>/dev/null; }
key() { head -c 16 /dev/urandom | hexdump -v -e '/1 "%02x"'; }
wait_api() { # until GET /api/control answers
  n=0; while [ "$n" -lt 120 ]; do
    out=$(api GET /api/control); [ "$(cat /tmp/xk-code)" = 200 ] && return 0
    sleep 2; n=$((n + 1)); done
  echo "XK_LAB_API=UNREACHABLE $out"; return 1
}
save_profile() { # save_profile ID YAML -> revision
  current=$(api GET "/api/profiles/$1"); rev=$(field "$current" '@.profile.revision')
  json=$(printf '%s' "$2" | sed 's/\\/\\\\/g; s/"/\\"/g' | awk 'BEGIN{ORS="\\n"}{print}')
  if [ -n "$rev" ]; then out=$(api PUT "/api/profiles/$1" "{\"source\":\"$json\",\"expected_revision\":\"$rev\"}")
  else out=$(api PUT "/api/profiles/$1" "{\"source\":\"$json\",\"expected_revision\":null}"); fi
  field "$out" '@.profile.revision'
}
apply_profile() { # apply_profile ID REV -> prints transaction/network JSON
  v=$(api POST "/api/profiles/$1/validate" "{\"expected_revision\":\"$2\"}")
  cand=$(field "$v" '@.validation.candidate_id')
  [ -n "$cand" ] || { echo "XK_LAB_VALIDATE=FAIL code=$(cat /tmp/xk-code) $v"; return 1; }
  a=$(api POST "/api/profiles/$1/apply" "{\"expected_revision\":\"$2\",\"candidate_id\":\"$cand\",\"idempotency_key\":\"$(key)\"}")
  [ "$(field "$a" '@.success')" = true ] || { echo "XK_LAB_APPLY=FAIL code=$(cat /tmp/xk-code) $a"; return 1; }
  echo "XK_LAB_APPLY=PASS"
}
start_gateway() { # Start -> status -> Confirm -> active, like startLanService
  s=$(api POST /api/control '{"action":"start"}')
  state=$(field "$s" '@.network.state')
  if [ "$state" != active ]; then
    tx=$(field "$s" '@.network.transaction_id'); token=$(field "$s" '@.network.confirm_token')
    [ "$state" = pending ] && [ -n "$tx" ] && [ -n "$token" ] || { echo "XK_LAB_START=FAIL code=$(cat /tmp/xk-code) $s"; return 1; }
    st=$(api GET /api/network/status)
    [ "$(field "$st" '@.network.transaction_id')" = "$tx" ] || { echo "XK_LAB_STATUS=FAIL $st"; return 1; }
    c=$(api POST /api/network/confirm "{\"transaction_id\":\"$tx\",\"confirm_token\":\"$token\"}")
    [ "$(field "$c" '@.network.state')" = confirmed ] || { echo "XK_LAB_CONFIRM=FAIL $c"; return 1; }
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
history_entries() { # accounted entries across the four history trees
  n=0; for t in history network-history active-event-history payloads; do
    [ -d "$ROOT/$t" ] && n=$((n + $(find "$ROOT/$t" -mindepth 1 | wc -l))); done; echo "$n"
}
references_intact() { # every snapshot a journal names exists
  for j in "$ROOT/recovery.json" "$ROOT"/network-history/*.json; do
    [ -f "$j" ] || continue
    keys="current_core previous_core baseline_core next_baseline_core"
    # A journal recovery closed RollbackDirect may record the very snapshot
    # whose absence ended it; only its candidate snapshot must remain.
    [ "$(jsonfilter -i "$j" -e '@.completion.kind' 2>/dev/null)" = rollback_direct ] && keys=current_core
    for k in $keys; do
      id=$(jsonfilter -i "$j" -e "@.$k.snapshot_id" 2>/dev/null) || continue
      [ -z "$id" ] || [ -d "$ROOT/history/$id" ] || { echo "XK_LAB_DANGLING=$j:$k:$id"; return 1; }
    done
  done
  return 0
}
