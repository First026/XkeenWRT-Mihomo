#!/bin/sh
# Run only in the marked disposable OpenWrt VM. The outer runner checks the
# guest identity; this test exercises the same public scenario interface.
set -eu
sentinel=/tmp/xkeenwrt-isolation-sentinel
[ "$(cat "$sentinel")" = xkeenwrt-sentinel-v1 ]
result=$(/usr/libexec/xkeenwrt-lab/isolation-lab probe)
[ "$result" = '{"scenario":"probe","result":"pass"}' ]
[ "$(cat "$sentinel")" = xkeenwrt-sentinel-v1 ]
