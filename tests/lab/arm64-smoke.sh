#!/bin/sh
# Run with an explicitly identified static AArch64 artifact and expected SHA-256.
set -eu
[ "$#" -eq 2 ] || { echo "usage: $0 <artifact> <sha256>" >&2; exit 2; }
artifact=$1
expected=$2
[ "${#expected}" -eq 64 ] && ! printf '%s' "$expected" | LC_ALL=C grep -q '[^0-9a-fA-F]' || { echo 'Expected SHA-256 must be exactly 64 hexadecimal characters' >&2; exit 2; }
expected=$(printf '%s' "$expected" | tr 'A-F' 'a-f')
qemu_image='multiarch/qemu-user-static@sha256:fe60359c92e86a43cc87b3d906006245f77bfc0565676b80004cc666e4feb9f0'
runner_image='python@sha256:a5a7017efc5969e00ae2b91c8eb0631049a569652aa4ffc4501769049ae45c72'
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
umask 077
tmp=$(mktemp -d)
qemu_container=
lab_container=
docker_local() {
    env -u DOCKER_HOST -u DOCKER_CONTEXT -u DOCKER_TLS -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH docker --host=unix:///var/run/docker.sock "$@"
}
cleanup() {
    [ -z "$lab_container" ] || docker_local rm -f "$lab_container" >/dev/null 2>&1 || :
    [ -z "$qemu_container" ] || docker_local rm -f "$qemu_container" >/dev/null 2>&1 || :
    rm -rf "$tmp"
}
trap cleanup EXIT HUP INT TERM
cp "$artifact" "$tmp/xkeenwrt-ui"
printf '%s  %s\n' "$expected" "$tmp/xkeenwrt-ui" | sha256sum -c -
qemu_container=$(docker_local create --pull=never --entrypoint /bin/true "$qemu_image")
docker_local cp "$qemu_container:/usr/bin/qemu-aarch64-static" "$tmp/qemu-aarch64-static"
printf '%s  %s\n' dce64b2dc6b005485c7aa735a7ea39cb0006bf7e5badc28b324b2cd0c73d883f "$tmp/qemu-aarch64-static" | sha256sum -c -
cp "$script_dir/arm64-smoke.py" "$tmp/arm64-smoke.py"
chmod 755 "$tmp/xkeenwrt-ui" "$tmp/qemu-aarch64-static"
chmod 644 "$tmp/arm64-smoke.py"
tar -C "$tmp" -cf "$tmp/inputs.tar" xkeenwrt-ui qemu-aarch64-static arm64-smoke.py
run_lab() {
    mode=$1
    lab_container=$(docker_local create -i --pull=never --network none --cap-drop ALL --security-opt no-new-privileges --read-only --tmpfs /tmp:rw,nosuid,nodev,size=64m --tmpfs /lab:rw,exec,nosuid,nodev,size=64m,mode=1777 --memory 512m --pids-limit 128 --user 1000:1000 "$runner_image" sh -ec 'tar -xf - -C /lab; exec python /lab/arm64-smoke.py "$1"' sh "$mode")
    set +e
    timeout 120s env -u DOCKER_HOST -u DOCKER_CONTEXT -u DOCKER_TLS -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH docker --host=unix:///var/run/docker.sock start -ai "$lab_container" < "$tmp/inputs.tar"
    start_status=$?
    set -e
    exit_status=$(docker_local inspect --format '{{.State.ExitCode}}' "$lab_container")
    running=$(docker_local inspect --format '{{.State.Running}}' "$lab_container")
    docker_local rm -f "$lab_container" >/dev/null
    lab_container=
    [ "$start_status" -ne 124 ] && [ "$running" = false ] || { echo 'Container timed out or did not stop' >&2; return 2; }
    if [ "$mode" = negative ]; then
        [ "$start_status" -ne 0 ] && [ "$exit_status" -eq 73 ] || { echo 'Injected process failure did not propagate' >&2; return 2; }
        echo 'PASS: injected inner process failure propagated as container failure'
    else
        [ "$start_status" -eq 0 ] && [ "$exit_status" -eq 0 ] || { echo "Smoke container failed: client=$start_status container=$exit_status" >&2; return 1; }
    fi
}
run_lab negative
run_lab normal
