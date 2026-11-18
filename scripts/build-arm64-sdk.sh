#!/usr/bin/env bash
set -euo pipefail
root_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
image='ghcr.io/openwrt/sdk@sha256:de8a21b5ac9b434abc62dda8d3957d890f18cbd955c6c32eb91c93184fe51e9a'
toolchain=/builder/staging_dir/toolchain-aarch64_cortex-a53_gcc-14.3.0_musl
cargo_home=${CARGO_HOME:-$HOME/.cargo}
rustup_home=${RUSTUP_HOME:-$HOME/.rustup}
cd "$root_dir"
docker_local=(env -u DOCKER_HOST -u DOCKER_CONTEXT -u DOCKER_TLS -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH docker --host=unix:///var/run/docker.sock)
[[ $(bun --version) == "$(cat "$root_dir/.bun-version")" ]] || { echo 'Wrong Bun version' >&2; exit 1; }
[[ $(rustc --version | awk '{print $2}') == 1.99.1 ]] || { echo 'Wrong Rust version' >&2; exit 1; }
rustup target list --installed | grep -Fxq aarch64-unknown-linux-musl || { echo 'Install the pinned Rust target first' >&2; exit 1; }
"${docker_local[@]}" image inspect "$image" >/dev/null || { echo 'Pull the pinned SDK image first' >&2; exit 1; }
(cd "$root_dir/frontend" && bun install --frozen-lockfile --offline && bun run build)
"${docker_local[@]}" run --rm --network none --user "$(id -u):$(id -g)" \
  -v "$root_dir:/work" -v "$cargo_home:/cargo" -v "$rustup_home:/rustup" \
  -w /work/backend -e HOME=/tmp -e CARGO_HOME=/cargo -e RUSTUP_HOME=/rustup \
  -e CARGO_TARGET_DIR=/work/backend/target/sdk-build -e PATH=/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
  -e STAGING_DIR=/builder/staging_dir \
  -e "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=$toolchain/bin/aarch64-openwrt-linux-musl-gcc" \
  -e "CC_aarch64_unknown_linux_musl=$toolchain/bin/aarch64-openwrt-linux-musl-gcc" \
  -e "AR_aarch64_unknown_linux_musl=$toolchain/bin/aarch64-openwrt-linux-musl-ar" \
  "$image" cargo rustc --offline --locked --release --target aarch64-unknown-linux-musl --bin xkeenwrt-ui -- -C link-arg=-Wl,-Map,/work/backend/target/sdk-link.map
printf 'Binary: %s\nLink map: %s\n' "$root_dir/backend/target/sdk-build/aarch64-unknown-linux-musl/release/xkeenwrt-ui" "$root_dir/backend/target/sdk-link.map"
