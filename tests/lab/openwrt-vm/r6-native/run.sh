#!/bin/sh
set -eu
[ "$#" -eq 0 ] || { echo "usage: $0" >&2; exit 2; }
owner=$(cat /proc/sys/kernel/random/uuid)
name="xkeen-openwrt-r6-native-$owner"
image=xkeen-openwrt-vm-r6-native:25.12.6
bounded_docker() {
  timeout -k 2 10 env -u DOCKER_HOST -u DOCKER_CONTEXT -u DOCKER_TLS -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH \
    docker --host=unix:///var/run/docker.sock "$@"
}
cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  if bounded_docker inspect "$name" >/dev/null 2>&1; then
    id=$(bounded_docker inspect --format '{{.Id}}' "$name")
    label=$(bounded_docker inspect --format '{{index .Config.Labels "org.xkeenwrt.vm.owner"}}' "$id")
    [ "$label" = "$owner" ] || { echo 'ERROR: container ownership mismatch; preserving it' >&2; exit 1; }
    bounded_docker rm -f "$id" >/dev/null 2>&1 || :
    if bounded_docker inspect "$id" >/dev/null 2>&1; then echo 'ERROR: owned container remains' >&2; exit 1; fi
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
bounded_docker create --pull never --name "$name" --label "org.xkeenwrt.vm.owner=$owner" --rm -i \
  --network none --cap-drop ALL --security-opt no-new-privileges --read-only --user 65534:65534 \
  --tmpfs /tmp:rw,nosuid,nodev,size=160m,mode=1777 --memory 768m --memory-swap 768m --pids-limit 96 --cpus 1 \
  --log-driver json-file --log-opt max-size=4m --log-opt max-file=1 \
  "$image" /bin/sh -ec 'truncate -s 128M /tmp/r6-persist.img; exec qemu-system-aarch64 -machine virt,accel=tcg -cpu cortex-a53 -m 768 -smp 1 -nodefaults -display none -monitor none -serial stdio -nic none -kernel /guest/Image -initrd /guest/rootfs.cpio -append "console=ttyAMA0 rdinit=/init quiet" -drive if=none,file=/tmp/r6-persist.img,format=raw,id=persist -device virtio-blk-device,drive=persist'
exec 3<&0
timeout --foreground -k 5 3600 env -u DOCKER_HOST -u DOCKER_CONTEXT -u DOCKER_TLS -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH \
  docker --host=unix:///var/run/docker.sock start -ai "$name" <&3
