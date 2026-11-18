#!/bin/sh
set +x
set -eu

version=0.1.26.2-r0
previous=0.1-r26
# apk-tools 3 rejects 0.1-r26.2; the release number moved into the version.
tag=v0.1.26.2
repo=First026/XkeenWRT-Mihomo
core="xkeenwrt-core-${version}.apk"
ui="xkeenwrt-ui-${version}.apk"

die() {
    printf 'XkeenWRT: %s\n' "$*" >&2
    exit 1
}

[ "$(id -u)" -eq 0 ] || die 'Выполните установку из SSH под root.'
[ -r /etc/openwrt_release ] || die 'Нужен OpenWrt.'
# shellcheck source=/dev/null
. /etc/openwrt_release
[ "${DISTRIB_ID:-}/${DISTRIB_RELEASE:-}/${DISTRIB_TARGET:-}/${DISTRIB_ARCH:-}" = \
    'OpenWrt/25.12.6/mediatek/filogic/aarch64_cortex-a53' ] ||
    die "APK $version предназначены для OpenWrt 25.12.6 mediatek/filogic (aarch64_cortex-a53)."
command -v apk >/dev/null 2>&1 || die 'Менеджер пакетов apk не найден.'

github_token=${XKEENWRT_GITHUB_TOKEN:-}
unset XKEENWRT_GITHUB_TOKEN
case "$github_token" in
    *[!a-zA-Z0-9_]*) die 'Недопустимый формат токена GitHub.' ;;
esac

installed() {
    apk --no-network info --exists "$@" >/dev/null 2>&1
}

show_panel() {
    lan_ip=$(ubus call network.interface.lan status 2>/dev/null |
        jsonfilter -e '@["ipv4-address"][0].address' 2>/dev/null || :)
    case "$lan_ip" in
        ''|*[!0-9.]*) lan_ip='<LAN-IP-роутера>' ;;
    esac
    printf 'Панель XkeenWRT %s: http://%s:1000/\n' "$version" "$lan_ip"
}

if installed "xkeenwrt-core=$version" "xkeenwrt-ui=$version"; then
    printf 'XkeenWRT %s уже установлен.\n' "$version"
    show_panel
    exit 0
fi
upgrade=
if installed "xkeenwrt-core=$previous" "xkeenwrt-ui=$previous"; then
    # In-place upgrade of the exact previous pair keeps /etc/xkeenwrt. The
    # service must be stopped first, as for a manual upgrade.
    if pidof mihomo >/dev/null 2>&1 || nft list table inet xkeenwrt >/dev/null 2>&1; then
        die 'Перед обновлением остановите сервис в панели (кнопка «Остановить») и повторите команду.'
    fi
    upgrade=1
elif installed xkeenwrt-core || installed xkeenwrt-ui; then
    die "Найдена другая или неполная установка XkeenWRT. Обновление поддерживается только с полной установки $previous."
fi

if ! command -v ubus >/dev/null 2>&1 || ! command -v uci >/dev/null 2>&1 ||
    ! command -v dnsmasq >/dev/null 2>&1 || ! installed firewall4 procd; then
    die 'Нужен штатный OpenWrt с procd, ubus, uci, firewall4 и dnsmasq.'
fi

cleanup() {
    for file in "$work_dir/$core" "$work_dir/$ui" "$work_dir/release.json"; do
        [ ! -f "$file" ] || rm -- "$file"
    done
    rmdir -- "$work_dir"
}

download_asset() {
    asset_file=$1
    set -- --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
        --connect-timeout 15 --max-time 180 --retry 2
    if [ -n "$github_token" ]; then
        # A private release is addressed by asset ID, looked up by file name.
        printf 'header = "Authorization: Bearer %s"\n' "$github_token" |
            curl --disable --config - --header 'Accept: application/vnd.github+json' "$@" \
                --output "$work_dir/release.json" "https://api.github.com/repos/$repo/releases/tags/$tag" ||
            return 1
        asset_id=$(jsonfilter -i "$work_dir/release.json" -e "@.assets[@.name='$asset_file'].id") || return 1
        rm -f -- "$work_dir/release.json"
        case "$asset_id" in ''|*[!0-9]*) return 1 ;; esac
        printf 'header = "Authorization: Bearer %s"\n' "$github_token" |
            curl --disable --config - --header 'Accept: application/octet-stream' "$@" \
                --output "$work_dir/$asset_file" "https://api.github.com/repos/$repo/releases/assets/$asset_id"
    else
        set -- "$@" --output "$work_dir/$asset_file"
        curl --disable "$@" "https://github.com/$repo/releases/download/$tag/$asset_file"
    fi
}

if [ "$#" -eq 2 ] && [ "$1" = '--from-dir' ]; then
    work_dir=$(cd -- "$2" && pwd -P) || die 'Каталог с APK не найден.'
else
    [ "$#" -eq 0 ] || die 'Использование: install.sh [--from-dir КАТАЛОГ]'
    if ! command -v curl >/dev/null 2>&1 || ! installed ca-bundle; then
        apk --update-cache add curl ca-bundle || die 'Не удалось установить curl и ca-bundle из настроенных репозиториев.'
    fi
    umask 077
    work_dir=$(mktemp -d /tmp/xkeenwrt-install.XXXXXX) || die 'Не удалось создать каталог в /tmp.'
    trap cleanup EXIT
    trap 'exit 1' HUP INT TERM

    printf 'Загрузка XkeenWRT %s с GitHub…\n' "$version"
    if ! download_asset "$core" || ! download_asset "$ui"; then
        die 'Не удалось скачать оба APK. Для закрытого релиза нужен доступ GitHub Contents: Read.'
    fi
fi
unset github_token

(
    cd "$work_dir"
    printf '%s  %s\n' \
        d5cdf2079259859c68ac789d9e00fbebd71747a5e9c85103e8dbdc445be34e44 "$core" \
        06574dc01e6b962db8e9ac83436ca016cb85f9e3cc709b6f5634ffd2074663ec "$ui" |
        sha256sum -c -
) || die 'Контрольная сумма APK не совпала.'

set --
for package in ca-bundle ip-full nftables-json kmod-nft-tproxy kmod-nft-socket kmod-nf-conntrack-netlink; do
    installed "$package" || set -- "$@" "$package"
done
if [ "$#" -gt 0 ]; then
    apk --update-cache add "$@" ||
        die 'Проверьте доступность feed для вашей прошивки и ABI ядра.'
fi

apk --no-network --repositories-file /dev/null --allow-untrusted --force-non-repository \
    add "$work_dir/$core" "$work_dir/$ui" || die 'Установка APK завершилась с ошибкой.'
installed "xkeenwrt-core=$version" "xkeenwrt-ui=$version" || die 'Не удалось подтвердить установку обоих APK.'
if [ -n "$upgrade" ]; then
    printf 'XkeenWRT обновлён с %s до %s. Профили, история и Mihomo сохранены.\n' "$previous" "$version"
fi
show_panel
