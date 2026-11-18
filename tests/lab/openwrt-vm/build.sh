#!/bin/sh
set -eu
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
verify_archive() {
  [ -f "$1" ] || { echo 'ERROR: pinned Mihomo archive missing' >&2; return 1; }
  printf '%s  %s\n' 223fab877e5795ce780ba39902e5f0b1113c1256ae244a7160f1165e017e9ccc "$1" | sha256sum -c -
}
if [ "${1:-}" = --test-preflight ] && [ "$#" -eq 1 ]; then
  tmp=$(mktemp -d)
  trap 'rm -rf -- "$tmp"' EXIT
  trap 'exit 1' HUP INT TERM
  if verify_archive "$tmp/missing.gz" >/dev/null 2>&1; then
    echo 'ERROR: missing archive accepted' >&2; exit 1
  fi
  printf 'synthetic incorrect archive\n' > "$tmp/wrong.gz"
  if verify_archive "$tmp/wrong.gz" >/dev/null 2>&1; then
    echo 'ERROR: incorrect archive accepted' >&2; exit 1
  fi
  echo 'PASS: missing and incorrect archive rejected before build'
  exit
fi
verify_arm_archive() {
  [ -f "$1" ] || { echo 'ERROR: pinned ARM64 Mihomo archive missing' >&2; return 1; }
  printf '%s  %s\n' daaf78a6240a282cdfd75bcbf98fe321f6bd52765cc29e79f344191198f0b50f "$1" | sha256sum -c -
}
verify_arm_elf() {
  readelf -h "$1" | grep -Eq 'Machine:.*AArch64' || return 1
  if readelf -l "$1" | grep -q INTERP || readelf -d "$1" 2>/dev/null | grep -q NEEDED; then return 1; fi
}
if [ "${1:-}" = --test-arm64-preflight ] && [ "$#" -eq 1 ]; then
  tmp=$(mktemp -d)
  trap 'rm -rf -- "$tmp"' EXIT
  trap 'exit 1' HUP INT TERM
  if verify_arm_archive "$tmp/missing.gz" >/dev/null 2>&1; then echo 'ERROR: missing archive accepted' >&2; exit 1; fi
  printf 'synthetic incorrect archive\n' > "$tmp/wrong.gz"
  if verify_arm_archive "$tmp/wrong.gz" >/dev/null 2>&1; then echo 'ERROR: incorrect archive accepted' >&2; exit 1; fi
  if verify_arm_elf /bin/true; then echo 'ERROR: non-ARM64 executable accepted' >&2; exit 1; fi
  echo 'PASS: missing/incorrect ARM64 archive and non-ARM64 ELF rejected'
  exit
fi
if [ "${1:-}" = --arm64 ] && [ "$#" -eq 1 ]; then
  repo=$(CDPATH= cd -- "$script_dir/../../.." && pwd)
  crate="$repo/tests/lab/validator"
  archive=/workspace/.cache/xkeenwrt/mihomo-linux-arm64-v1.19.34.gz
  [ -f "$crate/Cargo.lock" ] || { echo 'ERROR: validator Cargo.lock missing' >&2; exit 1; }
  verify_arm_archive "$archive"
  [ "$(id -u)" -ne 0 ] || { echo 'ERROR: build as an ordinary user' >&2; exit 1; }
  tmp=$(mktemp -d)
  trap 'rm -rf -- "$tmp"' EXIT
  trap 'exit 1' HUP INT TERM
  RUSTFLAGS='-C linker-flavor=ld.lld -C linker=rust-lld' cargo +1.99.1 build --manifest-path "$crate/Cargo.toml" --target-dir "$crate/target" --release --locked --offline --target aarch64-unknown-linux-musl
  for binary in isolation-lab isolation-probe; do
    cp "$crate/target/aarch64-unknown-linux-musl/release/$binary" "$tmp/$binary"
  done
  gzip -dc "$archive" > "$tmp/mihomo"
  printf '%s  %s\n' 022da41e03ce70641a2f50c485b4f69ade8f1c7aeeece2cf1ec45c614a029441 "$tmp/mihomo" | sha256sum -c -
  for binary in isolation-lab isolation-probe mihomo; do
    verify_arm_elf "$tmp/$binary" || { echo "ERROR: invalid or non-static ARM64 ELF: $binary" >&2; exit 1; }
    chmod 755 "$tmp/$binary"
    sha256sum "$tmp/$binary"
  done
  cp "$crate/fixtures/synthetic-ed25519-key.pem" "$tmp/synthetic-ed25519-key.pem"
  printf '%s  %s\n' c4932a9b6b97423b249a53e58d706f820185467464699038ed7ca5b29815ba03 "$tmp/synthetic-ed25519-key.pem" | sha256sum -c -
  chmod 644 "$tmp/synthetic-ed25519-key.pem"
  cp "$script_dir/Dockerfile.arm64" "$tmp/Dockerfile"
  : "${LAB_PROXY_CA:?Set LAB_PROXY_CA to the managed proxy CA file}"
  env -u DOCKER_HOST -u DOCKER_CONTEXT -u DOCKER_TLS -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH \
    docker --host=unix:///var/run/docker.sock build --target isolation \
      --secret "id=proxy_ca,src=$LAB_PROXY_CA" -t xkeen-openwrt-vm-arm64-isolation:25.12.6 "$tmp"
  exit
fi
if [ "${1:-}" = --arm64-baseline ] && [ "$#" -eq 1 ]; then
  : "${LAB_PROXY_CA:?Set LAB_PROXY_CA to the managed proxy CA file}"
  tmp=$(mktemp -d)
  trap 'rm -rf -- "$tmp"' EXIT
  trap 'exit 1' HUP INT TERM
  cp "$script_dir/Dockerfile.arm64" "$tmp/Dockerfile"
  env -u DOCKER_HOST -u DOCKER_CONTEXT -u DOCKER_TLS -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH \
    docker --host=unix:///var/run/docker.sock build --target baseline \
      --secret "id=proxy_ca,src=$LAB_PROXY_CA" -t xkeen-openwrt-vm-arm64:25.12.6 "$tmp"
  exit
fi
if [ "${1:-}" = --isolation ] && [ "$#" -eq 1 ]; then
  repo=$(CDPATH= cd -- "$script_dir/../../.." && pwd)
  crate="$repo/tests/lab/validator"
  archive=/workspace/.cache/xkeenwrt/mihomo-linux-amd64-v1.19.34.gz
  [ -f "$crate/Cargo.lock" ] || { echo 'ERROR: validator Cargo.lock missing' >&2; exit 1; }
  verify_archive "$archive"
  [ "$(id -u)" -ne 0 ] || { echo 'ERROR: build as an ordinary user' >&2; exit 1; }
  tmp=$(mktemp -d)
  trap 'rm -rf -- "$tmp"' EXIT
  trap 'exit 1' HUP INT TERM
  cargo +1.99.1 build --manifest-path "$crate/Cargo.toml" --target-dir "$crate/target" --release --locked --offline --target x86_64-unknown-linux-musl
  for binary in isolation-lab isolation-probe; do
    cp "$crate/target/x86_64-unknown-linux-musl/release/$binary" "$tmp/$binary"
  done
  gzip -dc "$archive" > "$tmp/mihomo"
  printf '%s  %s\n' 0a68807c7c93963bb66d07717fe0f3ac3945b422b525f8a1e19438d278d7ae11 "$tmp/mihomo" | sha256sum -c -
  for binary in isolation-lab isolation-probe mihomo; do
    readelf -h "$tmp/$binary" | grep -Eq 'Machine:.*Advanced Micro Devices X86-64' || { echo "ERROR: invalid ELF: $binary" >&2; exit 1; }
    if readelf -l "$tmp/$binary" | grep -q INTERP || readelf -d "$tmp/$binary" 2>/dev/null | grep -q NEEDED; then
      echo "ERROR: not a static executable: $binary" >&2; exit 1
    fi
    chmod 755 "$tmp/$binary"
    sha256sum "$tmp/$binary"
  done
  cp "$crate/fixtures/synthetic-ed25519-key.pem" "$tmp/synthetic-ed25519-key.pem"
  printf '%s  %s\n' c4932a9b6b97423b249a53e58d706f820185467464699038ed7ca5b29815ba03 "$tmp/synthetic-ed25519-key.pem" | sha256sum -c -
  chmod 644 "$tmp/synthetic-ed25519-key.pem"
  cp "$script_dir/Dockerfile.isolation" "$tmp/Dockerfile"
  : "${LAB_PROXY_CA:?Set LAB_PROXY_CA to the managed proxy CA file}"
  env -u DOCKER_HOST -u DOCKER_CONTEXT -u DOCKER_TLS -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH \
    docker --host=unix:///var/run/docker.sock build --secret "id=proxy_ca,src=$LAB_PROXY_CA" \
      -t xkeen-openwrt-vm-isolation:25.12.6 "$tmp"
  exit
fi
[ "$#" -eq 0 ] || { echo 'usage: build.sh [--isolation|--arm64|--arm64-baseline|--test-preflight|--test-arm64-preflight]' >&2; exit 2; }
: "${LAB_PROXY_CA:?Set LAB_PROXY_CA to the managed proxy CA file}"
env -u DOCKER_HOST -u DOCKER_CONTEXT -u DOCKER_TLS -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH \
  docker --host=unix:///var/run/docker.sock build \
  --secret "id=proxy_ca,src=$LAB_PROXY_CA" \
  -t xkeen-openwrt-vm:25.12.6 "$script_dir"
