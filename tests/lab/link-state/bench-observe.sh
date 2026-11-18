#!/bin/sh
# Read-only one-line observation for the bench cable/Wi-Fi check. Run on the
# bench router as root, e.g. every two seconds while plugging the cable.
# It prints interface state, presence of the generation's own nft table,
# rule and route, and the active record's phase/outcome. It changes nothing
# and prints no profile, subscription, key or client address.
set -u
LAN_PORT=${LAN_PORT:-eth1}
WIFI_IF=${WIFI_IF:-phy1-ap0}
J=/etc/xkeenwrt/recovery.json
A=/etc/xkeenwrt/active-reconcile.json
field() { jsonfilter -i "$1" -e "$2" 2>/dev/null || echo -; }
gen=$(field "$J" '@.generation')
table=$(field "$J" '@.current.route_table')
prio=$(field "$J" '@.current.priority')
if nft list table inet xkeenwrt >/dev/null 2>&1; then nft=present; else nft=absent; fi
rule=$(ip -4 rule show 2>/dev/null | grep -c "^$prio:")
route=$(ip -4 route show table "$table" 2>/dev/null | grep -c '^local default dev lo')
port=$(ip -j link show dev "$LAN_PORT" 2>/dev/null | jsonfilter -e '@[0].operstate' 2>/dev/null || echo -)
clients=$(iwinfo "$WIFI_IF" assoclist 2>/dev/null | grep -c '^[0-9A-Fa-f][0-9A-Fa-f]:')
event="$(field "$A" '@.event_id' | cut -c1-8) $(field "$A" '@.kind')/$(field "$A" '@.phase')"
result="action=$(field "$A" '@.action') outcome=$(field "$A" '@.outcome') error=$(field "$A" '@.error_code')@$(field "$A" '@.failed_phase')"
echo "$(date +%T) gen=$gen $LAN_PORT=$port wifi_clients=$clients nft=$nft rule=$rule route=$route event=$event $result"
