#!/bin/sh
# Only invoke as an unprivileged user outside the disposable guest.
set -eu
[ "$(id -u)" -ne 0 ] || { printf '%s\n' 'host refusal test requires an unprivileged user' >&2; exit 1; }
binary=${1:?supply supervisor binary}
output=$("$binary" probe 2>&1) && { printf '%s\n' 'unexpected success' >&2; exit 1; }
[ "$output" = '{"scenario":"probe","result":"unavailable"}' ] || { printf '%s\n' 'unexpected refusal output' >&2; exit 1; }
