#!/bin/sh
set -eu
owner=$(cat /proc/sys/kernel/random/uuid)
name="xkeen-openwrt-lab-$owner"
label=org.xkeenwrt.vm.owner
bounded_docker() {
  timeout -k 2 10 env -u DOCKER_HOST -u DOCKER_CONTEXT -u DOCKER_TLS -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH \
    docker --host=unix:///var/run/docker.sock "$@"
}
cleanup_owned() {
  target=$1
  expected=$2
  # Resolve a precise name to an immutable ID, then verify its immutable label.
  if ! ids=$(bounded_docker ps -a --no-trunc --filter "name=^/${target}$" --format '{{.ID}}'); then
    echo "ERROR: could not inspect container $target" >&2
    return 1
  fi
  [ -n "$ids" ] || return 0
  case "$ids" in *'
'*) echo "ERROR: ambiguous container name $target" >&2; return 1;; esac
  if ! identity=$(bounded_docker inspect --format '{{.Id}} {{index .Config.Labels "org.xkeenwrt.vm.owner"}}' "$ids"); then
    echo "ERROR: could not verify ownership of $target" >&2
    return 1
  fi
  if [ "$identity" != "$ids $expected" ]; then
    echo "ERROR: ownership mismatch for $target; preserving container" >&2
    return 1
  fi
  bounded_docker rm -f "$ids" >/dev/null 2>&1 || :
  if ! remaining=$(bounded_docker ps -a --no-trunc --filter "id=$ids" --format '{{.ID}}'); then
    echo "ERROR: could not verify removal of $target" >&2
    return 1
  fi
  if [ -n "$remaining" ]; then
    echo "ERROR: owned container $target remains after cleanup" >&2
    return 1
  fi
}
cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  if [ "${child:-}" ]; then kill "$child" 2>/dev/null || :; fi
  if ! cleanup_owned "$name" "$owner"; then exit 1; fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

[ "$#" -eq 0 ] || { echo 'usage: run-validator.sh' >&2; exit 2; }
timeout --foreground -k 5 20 env -u DOCKER_HOST -u DOCKER_CONTEXT -u DOCKER_TLS -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH \
  docker --host=unix:///var/run/docker.sock create --pull never --name "$name" --label "$label=$owner" --rm -i \
  --network none --cap-drop ALL --security-opt no-new-privileges --read-only \
  --user 65534:65534 --memory 768m --memory-swap 768m --pids-limit 64 --cpus 1 \
  --log-driver json-file --log-opt max-size=1m --log-opt max-file=1 \
  xkeen-openwrt-vm-validator-arm64-test:25.12.6 \
  qemu-system-aarch64 -machine virt,accel=tcg -cpu cortex-a53 -m 384 -smp 1 -nodefaults -no-reboot \
  -display none -monitor none -serial stdio -nic none -kernel /guest/Image -initrd /guest/rootfs.cpio \
  -append 'console=ttyAMA0 rdinit=/init quiet xkeenwrt.isolation_lab=1'

# Waiting on a background attach makes the shell's signal traps immediate.
exec 3<&0
timeout --foreground -k 5 300 env -u DOCKER_HOST -u DOCKER_CONTEXT -u DOCKER_TLS -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH \
  docker --host=unix:///var/run/docker.sock start -ai "$name" <&3 &
child=$!
status=0
wait "$child" || status=$?
child=
exit "$status"
