# Текущий комплект: 0.1.26.2

18 ноября 2026. ARM64 `aarch64_cortex-a53`, OpenWrt 25.12.6. Исходники — дерево коммита выпуска `v0.1.26.2` и свежий `frontend/dist` (отличаются только хеши APK в `install.sh` и `build-run-installer.sh`, вписанные после сборки, документы и два скрипта стенда `tests/lab/r26.2/lib.sh` и `setup.sh`, исправленные после первого прогона стенда; в пакеты стенд не входит); точный список файлов — `source-r26.2.list` внутри архива рецепта. Код — r26 и исправление «Применить» на работающем шлюзе (журнал).

| Объект | SHA-256 |
| --- | --- |
| Build ID | `8a1de3d1c384b0153856baa3d95e8bdce11ef1da646f7714de7515db3ee49247` |
| `xkeenwrt-core-0.1.26.2-r0.apk` | `d5cdf2079259859c68ac789d9e00fbebd71747a5e9c85103e8dbdc445be34e44` |
| `xkeenwrt-ui-0.1.26.2-r0.apk` | `06574dc01e6b962db8e9ac83436ca016cb85f9e3cc709b6f5634ffd2074663ec` |
| `xkeenwrt-r26.2-source.tar` | `8a99107f1b5da900653f97f14556a1e3044606d95ba24adc3513ee70434bd83b` |
| `xkeenwrt-r26.2-recipe.tar` | `d63cfec2889e31e2bd1cd0c0b2cf94e1d6e74a8f3561c46558f5175d01b5309b` |
| `xkeenwrt-install-r26.2.run` (6 779 462 байта) | `628a14a2afff566db1e5bf27396b7c26a67e648b0499b47db29e22d3e8fa4bfd` |

**Как собрано.** сборочная VM (Ubuntu aarch64) с toolchain, извлечённым из закреплённого образа SDK `ghcr.io/openwrt/sdk@sha256:de8a21b5…` (`SDK-PROVENANCE.json` сверен по SHA-256), рецепт `build-r26.2.sh` внутри архива рецепта. Rust 1.99.1, `aarch64-unknown-linux-musl`, Cargo `--offline --locked`; Bun 1.4.4 для `frontend/dist`; упаковка apk-tools 3.0.5. Порядок прежний: validator и recovery → `package-build-id.sh` → backend с версией и Build ID → `package-build.sh`. Отличие от r26: r26 собирали тем же образом SDK напрямую в Docker с `--network none`.

**Обезличивание.** Rust пишет в бинарники пути к исходникам для сообщений о панике. Рецепт задаёт `--remap-path-prefix`: `$HOME/.cargo` → `/cargo`, `$HOME/.rustup` → `/rustup`, каталог замороженных исходников → `/work`, как в контейнере r26. `build-run-installer.sh` пишет в payload `.run` владельца `0/0` (GNU tar и bsdtar). Проверка: распакованы оба APK; во всех файлах, метаданных `apk adbdump`, скрипте и заголовках `.run` нет имени пользователя, домашних путей, адресов tailnet, URI с учётными данными и ключей.

**Версия.** `0.1.26.2-r0`, а не `0.1-r26.2`: apk-tools 3.0.5 отвергает дробную часть после `-r`. Порядок: `0.1-r26 < 0.1.26.2-r0 < 0.1.27-r0`.

**После сборки** в `install.sh` и `scripts/build-run-installer.sh` вписаны SHA-256 этих APK, затем собран `.run`. Поэтому архив исходников содержит эти два файла в состоянии до правки хешей; на APK это не влияет.

Проверки:
- `apk adbdump`: версия `0.1.26.2-r0`, архитектура `aarch64_cortex-a53`; UI зависит от `xkeenwrt-core=0.1.26.2-r0`.
- Host по CI: frontend 63, backend 218 (4 ignored), recovery 93, validator 7, profile-policy 10, контракт хуков; fmt и Clippy `-D warnings` чисты.
- ARM64 OpenWrt VM: [С1–С4 пройдены](testing/2026-11-18-0.1.26.2-lab-acceptance.md) на этих APK и этом `.run`, включая обновление с 0.1-r26.

**Не проверялось.** Реальное устройство, подпись дистрибутива.
