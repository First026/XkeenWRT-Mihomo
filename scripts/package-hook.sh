#!/bin/sh
# Invoked by APK hooks; UI/runtime/recovery may start, but Mihomo and network capture never do.
set -eu
[ -z "${IPKG_INSTROOT:-}" ] || exit 0
operation=${1:?}; package=${2:?}
case "$package" in
  ui) services='xkeenwrt-runtime xkeenwrt-ui' ;;
  core) services='xkeenwrt-core xkeenwrt-recovery' ;;
  *) exit 1 ;;
esac
# OpenWrt's stock BusyBox omits stat. Read the numeric long-list fields
# only for fixed package-owned paths; reject every mode outside this contract.
file_meta() (
  format=$1
  path=$2
  [ ! -L "$path" ] || return 1
  line=$(LC_ALL=C command ls -ldn -- "$path" 2>/dev/null) || return 1
  set -f
  set -- $line
  [ "$#" -ge 5 ] || return 1
  case "$1" in
    -rw-------) mode=600 ;;
    drwx------) mode=700 ;;
    -rwxr-xr-x|drwxr-xr-x) mode=755 ;;
    *) return 1 ;;
  esac
  case "$2:$3:$5" in *[!0-9:]*) return 1 ;; esac
  case "$format" in
    '%u:%a') printf '%s:%s\n' "$3" "$mode" ;;
    '%u:%a:%h') printf '%s:%s:%s\n' "$3" "$mode" "$2" ;;
    '%u:%a:%h:%s') printf '%s:%s:%s:%s\n' "$3" "$mode" "$2" "$5" ;;
    '%s') printf '%s\n' "$5" ;;
    *) return 1 ;;
  esac
)
# APK does not veto changes when a script fails. The independent native
# rescue entrypoint owns bounded quiescence; no shell PID watchdog or network
# mutation is used here. Receipt and any un-cleared fence survive the package.
prepare() {
  kind=$1
  rescue_dir=/etc/xkeenwrt/rescue
  rescue="$rescue_dir/xkeenwrt-recovery"
  if [ ! -L /etc/xkeenwrt ] && [ -d /etc/xkeenwrt ] &&
     [ ! -L "$rescue_dir" ] && [ -d "$rescue_dir" ] &&
     [ ! -L "$rescue" ] && [ -f "$rescue" ] && [ -x "$rescue" ]; then
    "$rescue" "--prepare-$kind"
  else
    echo "XkeenWRT: persistent rescue unavailable; $kind cleanup not confirmed" >&2
    return 1
  fi
}
service_stopped() {
  service=$1
  case "$service" in
    xkeenwrt-runtime|xkeenwrt-ui|xkeenwrt-core|xkeenwrt-recovery) ;;
    *) return 1 ;;
  esac
  request="{\"name\":\"$service\"}"
  response=$(bounded 1 ubus call service list "$request" 2>/dev/null) || return 1
  [ -n "$response" ] || return 1
  service_json=$(printf '%s\n' "$response" | jsonfilter -e "@[\"$service\"]" 2>/dev/null) || service_json=
  if [ -z "$service_json" ]; then
    root_json=$(printf '%s\n' "$response" | jsonfilter -e '@' 2>/dev/null) || return 1
    [ -n "$root_json" ] && return 0
    return 1
  fi
  running=$(printf '%s\n' "$response" | jsonfilter -e "@[\"$service\"].instances.*.running" 2>/dev/null) || return 1
  [ -n "$running" ] || return 1
  for state in $running; do
    case "$state" in
      false) ;;
      true) return 1 ;;
      *) return 1 ;;
    esac
  done
  return 0
}
bounded() {
  seconds=$1
  shift
  if command -v timeout >/dev/null 2>&1; then
    timeout -k 1 "$seconds" "$@"
  elif [ "$1" = ubus ]; then
    shift
    ubus -t "$seconds" "$@"
  elif [ "$#" -eq 2 ] && [ "$2" = stop ]; then
    case "$1" in
      /etc/init.d/xkeenwrt-runtime|/etc/init.d/xkeenwrt-ui|/etc/init.d/xkeenwrt-core|/etc/init.d/xkeenwrt-recovery)
        ubus -t "$seconds" call service delete "{\"name\":\"${1##*/}\"}" ;;
      *) return 1 ;;
    esac
  else
    return 1
  fi
}
stop_and_confirm() {
  service=$1
  link="/etc/init.d/$service"
  target="/usr/libexec/xkeenwrt/init/$service"
  [ -L "$link" ] && [ "$(readlink "$link")" = "$target" ] || return 1
  bounded 3 "$link" stop >/dev/null 2>&1 || true
  attempt=0
  while [ "$attempt" -lt 4 ]; do
    if service_stopped "$service"; then
      return 0
    fi
    attempt=$((attempt + 1))
    sleep 0.1
  done
  return 1
}
fallback_stop_allowed() {
  service=$1
  case "$service" in
    xkeenwrt-runtime|xkeenwrt-ui) return 0 ;;
    xkeenwrt-core|xkeenwrt-recovery)
      config=/etc/xkeenwrt
      marker="$config/network-never-enabled"
      [ ! -L "$config" ] && [ -d "$config" ] || return 1
      [ "$(file_meta '%u:%a' "$config" 2>/dev/null)" = "0:700" ] || return 1
      [ ! -L "$marker" ] && [ -f "$marker" ] || return 1
      [ "$(file_meta '%u:%a:%h:%s' "$marker" 2>/dev/null)" = "0:600:1:23" ] || return 1
      [ ! -e "$config/recovery.json" ] && [ ! -L "$config/recovery.json" ] || return 1
      [ "$(cat "$marker" 2>/dev/null)" = "xkeenwrt-no-network-v1" ]
      ;;
    *) return 1 ;;
  esac
}
remove_owned_link() {
  service=$1
  link="/etc/init.d/$service"
  target="/usr/libexec/xkeenwrt/init/$service"
  [ -L "$link" ] && [ "$(readlink "$link")" = "$target" ] || return 0
  for rc in /etc/rc.d/[SK]*"$service"; do
    [ -L "$rc" ] || continue
    [ "$(readlink "$rc")" = "../init.d/$service" ] || continue
    rm -f "$rc"
  done
  rm -f "$link"
}
start_control_plane() {
  for service in xkeenwrt-recovery xkeenwrt-runtime xkeenwrt-ui; do
    link="/etc/init.d/$service"
    target="/usr/libexec/xkeenwrt/init/$service"
    [ -L "$link" ] && [ "$(readlink "$link")" = "$target" ] || return 1
    "$link" enable >/dev/null 2>&1 || return 1
  done
  for service in xkeenwrt-recovery xkeenwrt-runtime xkeenwrt-ui; do
    "/etc/init.d/$service" start >/dev/null 2>&1 || return 1
  done
}
private_file_matches() {
  path=$1
  value=$2
  size=$3
  newline=$(printf '\nX')
  newline=${newline%X}
  case "$value" in *"$newline") value=${value%?} ;; esac
  [ ! -L "$path" ] && [ -f "$path" ] || return 1
  [ "$(file_meta '%u:%a:%h:%s' "$path" 2>/dev/null)" = "0:600:1:$size" ] || return 1
  [ "$(cat "$path" 2>/dev/null)" = "$value" ]
}
publish_private() {
  path=$1
  value=$2
  size=$3
  parent=${path%/*}
  name=${path##*/}
  if [ -e "$path" ] || [ -L "$path" ]; then
    private_file_matches "$path" "$value" "$size"
    return $?
  fi
  temp="$parent/.bootstrap-$name.$$"
  [ ! -e "$temp" ] && [ ! -L "$temp" ] || return 1
  (umask 077; set -C; printf '%s' "$value" > "$temp") || return 1
  chmod 600 "$temp" || { rm -f "$temp"; return 1; }
  [ "$(file_meta '%u:%a:%h:%s' "$temp" 2>/dev/null)" = "0:600:1:$size" ] || {
    rm -f "$temp"
    return 1
  }
  if ln "$temp" "$path"; then
    rm -f "$temp"
    sync
    private_file_matches "$path" "$value" "$size"
    return $?
  fi
  rm -f "$temp"
  private_file_matches "$path" "$value" "$size"
}
initialize_fresh_runtime() {
  data=/etc/xkeenwrt
  if [ -L "$data" ] || { [ -e "$data" ] && [ ! -d "$data" ]; }; then
    echo 'XkeenWRT: unsafe persistent data path; control plane remains stopped' >&2
    return 1
  fi
  if [ ! -e "$data" ]; then
    (umask 077; mkdir "$data") || return 1
    chmod 700 "$data" || return 1
    sync
  fi
  [ "$(file_meta '%u:%a' "$data" 2>/dev/null)" = '0:700' ] || return 1

  owner=$data/owner-id
  if [ -e "$owner" ] || [ -L "$owner" ]; then
    [ ! -L "$owner" ] && [ -f "$owner" ] || return 1
    [ "$(file_meta '%u:%a:%h:%s' "$owner" 2>/dev/null)" = '0:600:1:36' ] || return 1
    owner_id=$(cat "$owner" 2>/dev/null) || return 1
  else
    for state in recovery.json network-generation network-never-enabled; do
      [ ! -e "$data/$state" ] && [ ! -L "$data/$state" ] || {
        echo 'XkeenWRT: existing network state has no owner; bootstrap refused' >&2
        return 1
      }
    done
    owner_id=$(cat /proc/sys/kernel/random/uuid 2>/dev/null) || return 1
    publish_private "$owner" "$owner_id" 36 || return 1
  fi
  case "$owner_id" in
    ????????-????-????-????-????????????) ;;
    *) return 1 ;;
  esac
  case "$owner_id" in
    *[!0-9a-f-]*) return 1 ;;
  esac

  generation=$data/network-generation
  never=$data/network-never-enabled
  if [ ! -e "$generation" ] && [ ! -L "$generation" ]; then
    [ ! -e "$data/recovery.json" ] && [ ! -L "$data/recovery.json" ] || return 1
    [ ! -e "$never" ] && [ ! -L "$never" ] || return 1
    publish_private "$generation" '0
' 2 || return 1
    publish_private "$never" 'xkeenwrt-no-network-v1
' 23 || return 1
  else
    [ ! -L "$generation" ] && [ -f "$generation" ] || return 1
    [ "$(file_meta '%u:%a:%h' "$generation" 2>/dev/null)" = '0:600:1' ] || return 1
    generation_size=$(file_meta '%s' "$generation" 2>/dev/null) || return 1
    [ "$generation_size" -ge 2 ] && [ "$generation_size" -le 21 ] || return 1
    generation_value=$(cat "$generation" 2>/dev/null) || return 1
    case "$generation_value" in
      ''|*[!0-9]*|0?*) return 1 ;;
    esac
    [ "$generation_size" -eq "$((${#generation_value} + 1))" ] || return 1
    # The persisted counter is a canonical u64 followed by exactly one newline.
    [ "$(tail -c 1 "$generation" | wc -l)" -eq 1 ] || return 1
    if [ "${#generation_value}" -eq 20 ]; then
      [ "$generation_value" = "18446744073709551615" ] ||
        [ "$(printf '%s\n%s\n' "$generation_value" 18446744073709551615 | LC_ALL=C sort | head -n 1)" = "$generation_value" ] || return 1
    fi
    # Never recreate this one-shot marker after the first network Apply.
    if [ -e "$never" ] || [ -L "$never" ]; then
      private_file_matches "$never" 'xkeenwrt-no-network-v1' 23 || return 1
    elif [ "$generation_value" = '0' ] && [ ! -e "$data/recovery.json" ] && [ ! -L "$data/recovery.json" ]; then
      # Complete an interrupted initial install, but never restore the marker
      # after a generation has been reserved for Network Apply.
      publish_private "$never" 'xkeenwrt-no-network-v1
' 23 || return 1
    fi
  fi
  publish_private "$data/runtime-enabled" 'xkeenwrt-runtime-v1
' 20 || return 1
  publish_private "$data/recovery-enabled" 'xkeenwrt-recovery-v1
' 21 || return 1
  # Validation is isolated and never starts the selected profile on the router.
  # Provision its deployment gate as part of the usable control plane.
  publish_private /etc/xkeenwrt-validator-enabled 'xkeenwrt-validation-v1
' 23 || return 1
}
migrate_legacy_mihomo() {
  legacy=/usr/libexec/xkeenwrt/mihomo
  expected=022da41e03ce70641a2f50c485b4f69ade8f1c7aeeece2cf1ec45c614a029441
  expected_size=57344126
  [ ! -L /usr/libexec/xkeenwrt ] && [ -d /usr/libexec/xkeenwrt ] || return 1
  [ "$(file_meta '%u:%a' /usr/libexec/xkeenwrt 2>/dev/null)" = '0:755' ] || return 1
  if [ -L /etc/xkeenwrt ] || { [ -e /etc/xkeenwrt ] && [ ! -d /etc/xkeenwrt ]; }; then
    echo 'XkeenWRT: unsafe configuration directory; Mihomo migration skipped' >&2
    return 1
  fi
  if [ ! -e /etc/xkeenwrt ]; then
    (umask 077; mkdir /etc/xkeenwrt) || return 1
  fi
  [ "$(file_meta '%u:%a' /etc/xkeenwrt 2>/dev/null)" = '0:700' ] || return 1
  active=/etc/xkeenwrt/mihomo-active
  if [ -e "$active" ] || [ -L "$active" ]; then
    [ ! -L "$active" ] && [ -f "$active" ] || return 1
    [ "$(file_meta '%u:%a:%h:%s' "$active" 2>/dev/null)" = '0:600:1:7' ] || return 1
    version=$(cat "$active" 2>/dev/null) || return 1
    case "$version" in
      1.19.33)
        expected=8c73570d9a5f388bc2f58eee0b347ccfab84fb3cf1a0f8f2cf5eac7005fbcdc0
        expected_size=57475198
        ;;
      1.19.34) ;;
      *) echo 'XkeenWRT: unsupported active Mihomo marker; migration skipped' >&2; return 1 ;;
    esac
    active_core=/usr/libexec/xkeenwrt/cores/$version/mihomo
    [ ! -L "$active_core" ] && [ -f "$active_core" ] && [ -x "$active_core" ] || return 1
    core_stat=$(file_meta '%u:%a:%h:%s' "$active_core" 2>/dev/null) || return 1
    case "$core_stat" in
      "0:755:1:$expected_size") ;;
      "0:755:2:$expected_size")
        [ -e "$legacy" ] && [ ! -L "$legacy" ] || return 1
        [ "$legacy" -ef "$active_core" ] || return 1
        ;;
      *) return 1 ;;
    esac
    actual=$(sha256sum "$active_core" 2>/dev/null) || return 1
    [ "${actual%% *}" = "$expected" ] || return 1
    return 0
  fi
  if [ ! -e "$legacy" ]; then
    return 0
  fi
  [ ! -L "$legacy" ] && [ -f "$legacy" ] && [ -x "$legacy" ] || return 1
  legacy_stat_full=$(file_meta '%u:%a:%h:%s' "$legacy" 2>/dev/null) || return 1
  case "$legacy_stat_full" in
    "0:755:1:$expected_size"|"0:755:2:$expected_size") ;;
    *) return 1 ;;
  esac
  actual=$(sha256sum "$legacy" 2>/dev/null) || return 1
  [ "${actual%% *}" = "$expected" ] || {
    echo 'XkeenWRT: old Mihomo binary does not match pinned r12 v1.19.34; migration skipped' >&2
    return 1
  }
  catalog=/usr/libexec/xkeenwrt/cores
  if [ -L "$catalog" ] || { [ -e "$catalog" ] && [ ! -d "$catalog" ]; }; then return 1; fi
  if [ ! -e "$catalog" ]; then mkdir "$catalog" || return 1; chmod 755 "$catalog" || return 1; fi
  [ "$(file_meta '%u:%a' "$catalog" 2>/dev/null)" = '0:755' ] || return 1
  version_dir=$catalog/1.19.34
  if [ -L "$version_dir" ] || { [ -e "$version_dir" ] && [ ! -d "$version_dir" ]; }; then return 1; fi
  if [ ! -e "$version_dir" ]; then mkdir "$version_dir" || return 1; chmod 755 "$version_dir" || return 1; fi
  [ "$(file_meta '%u:%a' "$version_dir" 2>/dev/null)" = '0:755' ] || return 1
  versioned=$version_dir/mihomo
  if [ -e "$versioned" ] || [ -L "$versioned" ]; then
    [ ! -L "$versioned" ] && [ -f "$versioned" ] || return 1
    versioned_stat=$(file_meta '%u:%a:%h:%s' "$versioned" 2>/dev/null) || return 1
    case "$versioned_stat" in
      "0:755:1:$expected_size") ;;
      "0:755:2:$expected_size")
        [ "$legacy" -ef "$versioned" ] || return 1
        ;;
      *) return 1 ;;
    esac
    actual=$(sha256sum "$versioned" 2>/dev/null) || return 1
    [ "${actual%% *}" = "$expected" ] || return 1
  else
    case "$legacy_stat_full" in
      "0:755:1:$expected_size") ;;
      *) return 1 ;;
    esac
    ln "$legacy" "$versioned" || return 1
  fi
  # The hard link keeps the exact old inode through APK's removal of the flat path.
  # The catalogue verifier sees nlink=1 after that removal; no second 55 MiB copy is needed.
  marker_tmp=/etc/xkeenwrt/.mihomo-active-migrate.$$
  (umask 077; printf '1.19.34' > "$marker_tmp") || return 1
  chmod 600 "$marker_tmp" || { rm -f "$marker_tmp"; return 1; }
  mv "$marker_tmp" "$active" || { rm -f "$marker_tmp"; return 1; }
  sync
}
unused_runtime_evidence() {
  data=/etc/xkeenwrt
  [ ! -L "$data" ] && [ -d "$data" ] || return 1
  [ "$(file_meta '%u:%a' "$data" 2>/dev/null)" = '0:700' ] || return 1
  if [ -e "$data/owner-id" ] || [ -L "$data/owner-id" ]; then
    fallback_stop_allowed xkeenwrt-core || return 1
    private_file_matches "$data/network-generation" '0' 2 || return 1
  else
    # r12 could serve its editor before runtime was provisioned at all. Do
    # not invent the never-enabled marker: require an unprovisioned, stopped
    # core and no authoritative runtime/history state instead.
    for state in network-generation network-never-enabled transaction.json payloads history network-history active-history; do
      [ ! -e "$data/$state" ] && [ ! -L "$data/$state" ] || return 1
    done
    service_stopped xkeenwrt-core || return 1
  fi
  for state in recovery.json removal.json rescue-replacement.json active-reconcile.json; do
    [ ! -e "$data/$state" ] && [ ! -L "$data/$state" ] || return 1
  done
  # Stock OpenWrt has no timeout applet. This fixed read enumerates table
  # headers only; it never dumps rules/sets or performs a network mutation.
  tables=$(nft -j list tables) || return 1
  [ -n "$(printf '%s' "$tables" | jsonfilter -e '@.nftables' 2>/dev/null)" ] || return 1
  names=$(printf '%s' "$tables" | jsonfilter -e '@.nftables[*].table.name' 2>/dev/null) || names=
  for name in $names; do [ "$name" != xkeenwrt ] || return 1; done
}
prepare_unused_upgrade() {
  # Older installs provisioned rescue only on first activation. Absence of
  # rescue alone is not permission to treat an existing network as inactive.
  data=/etc/xkeenwrt
  [ ! -e "$data/rescue" ] && [ ! -L "$data/rescue" ] || return 1
  unused_runtime_evidence || return 1
  for service in xkeenwrt-ui xkeenwrt-runtime xkeenwrt-core xkeenwrt-recovery; do
    stop_and_confirm "$service" || return 1
  done
  unused_runtime_evidence || return 1
  group=/sys/fs/cgroup/xkeenwrt
  if [ -e "$group" ] || [ -L "$group" ]; then
    [ ! -L "$group" ] && [ -d "$group" ] || return 1
    [ "$(sed -n 's/^populated //p' "$group/cgroup.events")" = 0 ] || return 1
  fi
  echo 'XkeenWRT: never-activated legacy services stopped; network unchanged' >&2
}
case "$operation" in
  install)
    for service in $services; do
      target="/usr/libexec/xkeenwrt/init/$service"
      link="/etc/init.d/$service"
      if [ -L "$link" ]; then
        [ "$(readlink "$link")" = "$target" ] || { echo "foreign init link: $link" >&2; exit 1; }
      elif [ -e "$link" ]; then
        echo "foreign init file: $link" >&2; exit 1
      else
        ln -s "$target" "$link" || exit 1
      fi
    done
    if [ "$package" = ui ]; then
      initialize_fresh_runtime || {
        echo 'XkeenWRT: trusted control-plane bootstrap failed; UI/runtime/recovery were not started' >&2
        exit 1
      }
      start_control_plane || echo "XkeenWRT: UI/runtime installed but procd start failed" >&2
    fi
    ;;
  upgrade)
    # Quiesce while the legacy executable still has its original identity.
    # APK can continue on a failing hook; persistent recovery retains the fence.
    prepared=0
    if prepare upgrade || prepare_unused_upgrade; then prepared=1; fi
    # APK continues after a failing pre-upgrade. Preserve the verified inode
    # even when cleanup is pending; this does not clear any lifecycle fence.
    migrate_legacy_mihomo || {
      echo 'XkeenWRT: pinned Mihomo migration failed; core preservation failed; upgrade is not accepted for runtime use' >&2
      exit 1
    }
    [ "$prepared" -eq 1 ] || {
      echo 'XkeenWRT: Mihomo preserved; upgrade cleanup remains pending; rescue and fences retained' >&2
      exit 1
    }
    ;;
  remove)
    prepared=0
    if prepare remove; then
      prepared=1
    else
      echo "XkeenWRT: attempting fixed service stops; unresolved links and rescue are retained" >&2
    fi
    for service in $services; do
      if [ "$prepared" -eq 1 ]; then
        if ! service_stopped "$service"; then
          if ! stop_and_confirm "$service"; then
            echo "XkeenWRT: $service still running; init links retained" >&2
            continue
          fi
        fi
        remove_owned_link "$service"
      elif fallback_stop_allowed "$service" && stop_and_confirm "$service"; then
        remove_owned_link "$service"
      else
        echo "XkeenWRT: $service stop not confirmed; init links retained" >&2
      fi
    done
    ;;
  *) exit 1 ;;
esac
