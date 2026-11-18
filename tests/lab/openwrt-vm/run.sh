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

# The fixed test creates one sentinel of its own, provokes a name collision and
# confirms that the mismatched token cannot remove it. No caller-supplied name.
if [ "${1:-}" = '--test-ownership' ] && [ "$#" -eq 1 ]; then
  wrong_owner=$owner
  owner=$(cat /proc/sys/kernel/random/uuid)
  sentinel=$(bounded_docker create --pull never --name "$name" --label "$label=$owner" \
    --network none --cap-drop ALL --security-opt no-new-privileges --read-only \
    --user 65534:65534 --memory 64m --memory-swap 64m --pids-limit 16 \
    xkeen-openwrt-vm:25.12.6 true)
  if bounded_docker create --pull never --name "$name" --label "$label=$wrong_owner" \
    --network none xkeen-openwrt-vm:25.12.6 true >/dev/null 2>&1; then
    echo 'ERROR: expected a name collision' >&2; exit 1
  fi
  if cleanup_owned "$name" "$wrong_owner" 2>/dev/null; then
    echo 'ERROR: mismatched ownership was accepted' >&2; exit 1
  fi
  if ! actual=$(bounded_docker inspect --format '{{.Id}}' "$sentinel") || [ "$actual" != "$sentinel" ]; then
    echo 'ERROR: sentinel was not preserved' >&2; exit 1
  fi
  echo 'PASS: collision and mismatched owner preserved sentinel; verified owner cleanup follows'
  exit 0
fi
image=xkeen-openwrt-vm:25.12.6
memory=512m
guest_memory=256
append='console=ttyS0 rdinit=/init quiet'
qemu=qemu-system-x86_64
machine=pc,accel=tcg
kernel=/guest/bzImage
initrd=/guest/rootfs.cpio.gz
if [ "${1:-}" = --isolation ] && [ "$#" -eq 1 ]; then
  image=xkeen-openwrt-vm-isolation:25.12.6
  memory=768m
  guest_memory=384
  append='console=ttyS0 rdinit=/init quiet xkeenwrt.isolation_lab=1'
  set -- -cpu max
elif [ "${1:-}" = --arm64 ] && [ "$#" -eq 1 ]; then
  image=xkeen-openwrt-vm-arm64-isolation:25.12.6
  memory=768m
  guest_memory=384
  qemu=qemu-system-aarch64
  machine=virt,accel=tcg
  kernel=/guest/Image
  initrd=/guest/rootfs.cpio
  append='console=ttyAMA0 rdinit=/init quiet xkeenwrt.isolation_lab=1'
  set -- -cpu cortex-a53
elif [ "${1:-}" = --arm64-baseline ] && [ "$#" -eq 1 ]; then
  image=xkeen-openwrt-vm-arm64:25.12.6
  memory=768m
  guest_memory=384
  qemu=qemu-system-aarch64
  machine=virt,accel=tcg
  kernel=/guest/Image
  initrd=/guest/rootfs.cpio
  append='console=ttyAMA0 rdinit=/init quiet'
  set -- -cpu cortex-a53
elif [ "$#" -ne 0 ]; then
  echo 'usage: run.sh [--isolation|--arm64|--arm64-baseline|--test-ownership]' >&2; exit 2
else
  set --
fi
# The image is local; never pull or mount a workspace while running the guest.
timeout --foreground -k 5 20 env -u DOCKER_HOST -u DOCKER_CONTEXT -u DOCKER_TLS -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH \
  docker --host=unix:///var/run/docker.sock create --pull never --name "$name" --label "$label=$owner" --rm -i \
  --network none --cap-drop ALL --security-opt no-new-privileges --read-only \
  --user 65534:65534 --memory "$memory" --memory-swap "$memory" --pids-limit 64 --cpus 1 \
  --log-driver json-file --log-opt max-size=1m --log-opt max-file=1 \
  "$image" \
  "$qemu" -machine "$machine" "$@" -m "$guest_memory" -smp 1 -nodefaults -no-reboot \
  -display none -monitor none -serial stdio -nic none -kernel "$kernel" -initrd "$initrd" \
  -append "$append"

# Waiting on a background attach makes the shell's signal traps immediate.
exec 3<&0
timeout --foreground -k 5 180 env -u DOCKER_HOST -u DOCKER_CONTEXT -u DOCKER_TLS -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH \
  docker --host=unix:///var/run/docker.sock start -ai "$name" <&3 &
child=$!
status=0
wait "$child" || status=$?
child=
exit "$status"
