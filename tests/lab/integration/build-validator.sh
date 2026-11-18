#!/bin/sh
set -eu
[ "$#" -eq 0 ] || { echo 'usage: build-validator.sh' >&2; exit 2; }
[ "$(id -u)" -ne 0 ] || { echo 'ERROR: build as an ordinary user' >&2; exit 1; }
: "${LAB_PROXY_CA:?Set LAB_PROXY_CA}"
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo=$(CDPATH= cd -- "$script_dir/../../.." && pwd)
source_dir=${XKEEN_LAB_VALIDATOR_SNAPSHOT:-$repo}
[ -f "$source_dir/validator/Cargo.lock" ] && [ -d "$source_dir/crates/profile-policy" ] || { echo 'ERROR: validator source missing' >&2; exit 1; }
[ "$repo" = /workspace/XkeenWRT-Mihomo ] || { echo 'ERROR: fixed test executable path differs' >&2; exit 1; }
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT
trap 'exit 1' HUP INT TERM
cargo +1.99.1 test --manifest-path "$source_dir/validator/Cargo.toml" --target-dir "$repo/validator/target" --target x86_64-unknown-linux-musl --no-run --locked --offline --message-format=json > "$tmp/artifacts.json"
python3 - "$tmp/artifacts.json" "$tmp" <<'PY'
import json, pathlib, shutil, sys
artifacts = [json.loads(line) for line in pathlib.Path(sys.argv[1]).read_text().splitlines()]
protocols = [x['executable'] for x in artifacts if x.get('reason') == 'compiler-artifact' and x.get('target', {}).get('name') == 'protocol' and x.get('profile', {}).get('test') and x.get('executable')]
if len(protocols) != 1 or not protocols[0].startswith('/workspace/XkeenWRT-Mihomo/validator/target/x86_64-unknown-linux-musl/debug/deps/'):
    sys.exit('ERROR: unexpected test artifact')
shutil.copyfile(protocols[0], pathlib.Path(sys.argv[2]) / 'protocol-test')
shutil.copyfile('/workspace/XkeenWRT-Mihomo/validator/target/x86_64-unknown-linux-musl/debug/xkeenwrt-validate', pathlib.Path(sys.argv[2]) / 'xkeenwrt-validate')
PY
cargo +1.99.1 build --manifest-path "$source_dir/validator/Cargo.toml" --target-dir "$repo/validator/target" --target x86_64-unknown-linux-musl --release --locked --offline
cp "$repo/validator/target/x86_64-unknown-linux-musl/release/xkeenwrt-validate" "$tmp/xkeenwrt-validate-production"
cargo +1.99.1 build --manifest-path "$source_dir/validator/Cargo.toml" --target-dir "$repo/validator/target" --target x86_64-unknown-linux-musl --release --features lab-faults --locked --offline
cp "$repo/validator/target/x86_64-unknown-linux-musl/release/xkeenwrt-validate" "$tmp/xkeenwrt-validate-lab"
python3 - "$source_dir" "$tmp" <<'PYFIXTURES'
import base64, json, pathlib, sys
repo, tmp = map(pathlib.Path, sys.argv[1:])
fixtures = repo / 'crates/profile-policy/tests/fixtures'
requests = tmp / 'requests'
requests.mkdir()
configs = {
    'valid': (fixtures / 'effective-inline.json').read_text(),
    'vless': (fixtures / 'effective-vless.json').read_text(),
    'provider': (fixtures / 'effective-provider.json').read_text(),
    'rule-provider': (fixtures / 'effective-rule-provider.json').read_text(),
    'invalid': 'mode: [\n',
    'missing': 'mode: rule\nproxies: []\nrules:\n  - GEOIP,CN,DIRECT\n  - MATCH,DIRECT\n',
}
provider = base64.b64encode((fixtures / 'provider-payload.yaml').read_bytes()).decode('ascii')
rule_provider = base64.b64encode((fixtures / 'rule-payload.yaml').read_bytes()).decode('ascii')
for name, config in configs.items():
    assets = ([{'path': 'providers/proxies/0.yaml', 'content_base64': provider}] if name == 'provider' else
              [{'path': 'providers/rules/0.yaml', 'content_base64': rule_provider}] if name == 'rule-provider' else [])
    (requests / (name + '.json')).write_text(json.dumps({'version': 1, 'config': config, 'assets': assets}, separators=(',', ':')))
(requests / 'rule-provider-missing.json').write_text(json.dumps({'version': 1, 'config': configs['rule-provider'], 'assets': []}, separators=(',', ':')))
(requests / 'provider-missing.json').write_text(json.dumps({'version': 1, 'config': configs['provider'], 'assets': []}, separators=(',', ':')))
PYFIXTURES
archive=/workspace/.cache/xkeenwrt/mihomo-linux-amd64-v1.19.34.gz
printf '%s  %s\n' 223fab877e5795ce780ba39902e5f0b1113c1256ae244a7160f1165e017e9ccc "$archive" | sha256sum -c -
gzip -dc "$archive" > "$tmp/mihomo"
printf '%s  %s\n' 0a68807c7c93963bb66d07717fe0f3ac3945b422b525f8a1e19438d278d7ae11 "$tmp/mihomo" | sha256sum -c -
for binary in protocol-test xkeenwrt-validate xkeenwrt-validate-production xkeenwrt-validate-lab mihomo; do
  readelf -h "$tmp/$binary" | grep -Eq 'Machine:.*Advanced Micro Devices X86-64' || exit 1
  if readelf -l "$tmp/$binary" | grep -q INTERP || readelf -d "$tmp/$binary" 2>/dev/null | grep -q NEEDED; then echo 'ERROR: динамический ELF' >&2; exit 1; fi
  chmod 755 "$tmp/$binary"
  sha256sum "$tmp/$binary"
done
image_id=$(env -u DOCKER_HOST -u DOCKER_CONTEXT -u DOCKER_TLS -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH \
  docker --host=unix:///var/run/docker.sock image inspect xkeen-openwrt-vm:25.12.6 --format '{{.Id}}')
[ "$image_id" = 'sha256:4c7477b7851e7d9788771d7532f70109d76292627a9017ce0f6b68e04827a052' ] || {
  echo 'ERROR: baseline image ID differs from the pinned lab image' >&2; exit 1;
}
cp "$script_dir/Dockerfile.validator" "$tmp/Dockerfile"
env -u DOCKER_HOST -u DOCKER_CONTEXT -u DOCKER_TLS -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH \
  docker --host=unix:///var/run/docker.sock build --secret "id=proxy_ca,src=$LAB_PROXY_CA" -t xkeen-openwrt-vm-validator-test:25.12.6 "$tmp"
