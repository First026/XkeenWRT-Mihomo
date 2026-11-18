# ARM64 build baseline

Текущий пакетный срез собирается из отдельного frozen source/recipe; его версия, точные исходники, команды, build ID, результаты и ограничения записаны в [arm64-current-build.md](arm64-current-build.md). Текст ниже описывает более ранний userspace baseline.

Это лабораторный userspace-бинарник, не APK и не разрешение на установку. Цель — OpenWrt 25.12.6 mediatek/filogic, package architecture `aarch64_cortex-a53`, Rust target `aarch64-unknown-linux-musl`. Никакие kernel modules не собирались и не устанавливались.

## Происхождение SDK

Официальный [OpenWrt Docker README](https://github.com/openwrt/docker/blob/333c887910922b3254590da704ac2876ec212ef4/README.md) описывает SDK в GHCR и формат тегов. 12 ноября 2026 GHCR вернул для `ghcr.io/openwrt/sdk:mediatek-filogic-25.12.6` manifest digest `sha256:de8a21b5ac9b434abc62dda8d3957d890f18cbd955c6c32eb91c93184fe51e9a`; образ загружен по digest. В его config указаны target `mediatek/filogic`, release `25.12.6` и revision проекта контейнера `333c887910922b3254590da704ac2876ec212ef4`. В образе действительно есть SDK, а не только загрузчик.

В образе `sha256sums_min` содержит `1c04ac47bdfc361d6aab299eb520d570e368013dedcb8d29cf39dc7168ae642e *openwrt-sdk-25.12.6-mediatek-filogic_gcc-14.3.0_musl.Linux-x86_64.tar.zst`. Это сохранённая внутри образа запись, а не независимо скачанный и проверенный здесь архив. [Setup script](https://github.com/openwrt/docker/blob/333c887910922b3254590da704ac2876ec212ef4/setup.sh) проверяет подпись списка и checksum архива при создании образа; эту проверку заново здесь не проводили. Прямая загрузка с `downloads.openwrt.org` через настроенный proxy ответила HTTP 403; обхода не было.

В SDK `include/version.mk` фиксирует `r33311-981c978eff`, совпадающий с наблюдаемым revision устройства. `feeds.conf.default` фиксирует базовый исходный код `64900e756efa667774214f9c6b17c113222e01f7`, совпадающий с peeled официальным тегом `v25.12.6`; остальные feed revisions находятся в том же файле SDK. `info.mk` указывает GCC 14.3.0 и musl 1.2.5. SDK указывает kernel 6.12.112 и SHA-256 исходника ядра `164dc9d1f6c93c61a15e1f071c48379b467f2b17c469cce7223471968208ed03`. Это не ABI hash: устройство сообщает kernel package `6.12.112~f0a7348f9cb959e1bf4d0447669b031e-r1`. Происхождение прошивки и feed устройства и совпадение ABI kmod не подтверждены; одинаковая версия ядра этого не доказывает.

## Сборка

Нужны Docker с доступом к официальному GHCR, Rust 1.99.1 с установленным target, Bun версии из `.bun-version`, а также заранее загруженные зависимости Cargo и Bun. Например, после установки этих инструментов и загрузки зависимостей обычным разрешённым способом:

```sh
rustup target add aarch64-unknown-linux-musl
(cd backend && cargo fetch --locked --target aarch64-unknown-linux-musl)
(cd frontend && bun install --frozen-lockfile)
env -u DOCKER_HOST -u DOCKER_CONTEXT -u DOCKER_TLS -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH \
  docker --host=unix:///var/run/docker.sock pull ghcr.io/openwrt/sdk@sha256:de8a21b5ac9b434abc62dda8d3957d890f18cbd955c6c32eb91c93184fe51e9a
./scripts/build-arm64-sdk.sh
file backend/target/sdk-build/aarch64-unknown-linux-musl/release/xkeenwrt-ui
readelf -h -l -d backend/target/sdk-build/aarch64-unknown-linux-musl/release/xkeenwrt-ui
sha256sum backend/target/sdk-build/aarch64-unknown-linux-musl/release/xkeenwrt-ui
```

Скрипт использует локальный Docker socket, не меняя конфигурацию и credentials Docker. Frontend строится из lockfile с `bun install --offline`; Cargo работает с `--locked --offline` в SDK-контейнере с `--network none`. Для SDK используется отдельный Cargo target directory: общие host build scripts могут зависеть от более новой glibc, чем есть в контейнере. Script не скачивает зависимости, не запускает setup.sh и не собирает kernel. Build cache и выходные файлы остаются вне Git. Команды зафиксированы, но повторные локальные сборки дали разные SHA-256; побайтовая воспроизводимость не установлена. Для проверки конкретного артефакта всегда нужен его фактический checksum.

Компилятор C и linker — SDK `aarch64-openwrt-linux-musl-gcc`; настройки `target-cpu=native` не используются. Link map `backend/target/sdk-link.map` показывает, что Rust 1.99.1 использует собственные `self-contained/crt1.o`, `crti.o`, `crtbegin.o`, `libunwind.a`, `libc.a`, `crtend.o` и `crtn.o`. Следовательно, нельзя утверждать, что бинарник связан с musl из SDK только на основании имени linker. Статическая сборка не требует динамического загрузчика или shared libraries; ей всё равно нужны подходящие CPU и системные вызовы Linux. Это не проверка работы на роутере или совместимости ABI модулей.

После реализации preparation preview главный агент повторно выполнил полный скрипт 12 ноября 2026. Получен ELF64 little-endian AArch64, статический, stripped, размер 2 756 984 байта, SHA-256 `833fb45145e96843a33a141e3a3027ac1a98999fb3bcc1b084dab186c6af7eba`; `readelf` не показывает `INTERP`, динамическую секцию или `NEEDED` libraries. Расширенный smoke прошёл на этом артефакте. Это evidence конкретного локального результата, а не обещание идентичного хеша при повторной сборке.
