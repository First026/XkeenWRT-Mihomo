# Текущий комплект: 0.1.26.3

18 ноября 2026. ARM64 `aarch64_cortex-a53`, OpenWrt 25.12.6. Исходники — дерево коммита выпуска `v0.1.26.3` и свежий `frontend/dist` (отличаются только хеши APK в `install.sh` и `build-run-installer.sh`, вписанные после сборки, документы и комментарии в коде); точный список файлов — `source-r26.3.list` внутри архива рецепта. Код — 0.1.26.2 и запуск через Tailscale из 0.1.26.1 ([решение 024](decisions/024-tailscale-start.md), журнал), `ruzstd` 0.9.1 и исправленный `picomatch` для сборки фронтенда ([происхождение](UPSTREAM.md)).

| Объект | SHA-256 |
| --- | --- |
| Build ID | `eb9236e159f64e5fb378c20cce4eb6b1f9ce49ec71c79d882281e439d13ef527` |
| `xkeenwrt-core-0.1.26.3-r0.apk` | `45f7f5f17b0f5acd811bf53ea1f371581b18de3b247d9e7d9cadc5a292e20e6d` |
| `xkeenwrt-ui-0.1.26.3-r0.apk` | `64faf1b3db1d5adf525aaa32ed7bac8f15f6f9bd77d57a4ec2a202b6fe71c5f2` |
| `xkeenwrt-r26.3-source.tar` | `baadec1f440a548018b7e3fccd4845771169a53033156c0f3148a0c915d987ba` |
| `xkeenwrt-r26.3-recipe.tar` | `bfbf188057db9a6a00c44914cfbda003a6c793ea488971837ba6e247dd04bd32` |
| `xkeenwrt-install-r26.3.run` (6 799 942 байта) | `3c39647495f10c7e1de24b224a061f3b9100c26639014038449f893360adf0ea` |

**Как собрано.** Как 0.1.26.2: сборочная VM (Ubuntu aarch64) с toolchain, извлечённым из закреплённого образа SDK `ghcr.io/openwrt/sdk@sha256:de8a21b5…` (`SDK-PROVENANCE.json` сверен по SHA-256), рецепт `build-r26.3.sh` внутри архива рецепта, отдельный пустой каталог `target`. Rust 1.99.1, `aarch64-unknown-linux-musl`, Cargo `--offline --locked`; Bun 1.4.4 для `frontend/dist`; упаковка apk-tools 3.0.5. Порядок прежний: validator и recovery → `package-build-id.sh` → backend с версией и Build ID → `package-build.sh`.

**Обезличивание.** Как в 0.1.26.2: `--remap-path-prefix` для `$HOME/.cargo`, `$HOME/.rustup` и замороженных исходников, владелец payload `.run` — `0/0`. Проверка: распакованы оба APK; во всех файлах, метаданных `apk adbdump`, скрипте и заголовках `.run` нет имени пользователя, домашних путей, адресов tailnet, URI с учётными данными и ключей. Тем же шаблоном просмотрены сырые байты всех файлов обоих APK и payload `.run` и распакованные `.gz` веб-бандла, который `rust-embed` вшивает в бинарник сжатым: совпадений нет.

**Версия.** `0.1.26.3-r0`, а не `0.1-r26.3`: apk-tools 3.0.5 отвергает дробную часть после `-r`. Порядок: `0.1.26.2-r0 < 0.1.26.3-r0 < 0.1.27-r0`.

**После сборки** в `install.sh` и `scripts/build-run-installer.sh` вписаны SHA-256 этих APK, затем собран `.run`. Поэтому архив исходников содержит эти два файла в состоянии до правки хешей; на APK это не влияет.

Проверки:
- `apk adbdump`: версия `0.1.26.3-r0`, архитектура `aarch64_cortex-a53`; UI зависит от `xkeenwrt-core=0.1.26.3-r0`.
- Host по CI: frontend 70, backend 230 (4 ignored), recovery 99, validator 7, profile-policy 10, контракт хуков; fmt и Clippy `-D warnings` чисты.
- `frontend/dist` (27 файлов) побайтно совпадает со сборкой до замены `picomatch` и `shadcn` на вендорные копии (Build ID `4ad22b0e…`): веб-бандл в `xkeenwrt-ui` тот же. Изменились только архив исходников внутри APK и, вслед за ним, хеши.
- ARM64 OpenWrt VM: [С1–С7 пройдены](testing/2026-11-18-0.1.26.3-lab-acceptance.md) на этих APK и этом `.run`, включая обновление с 0.1.26.2.

**Не проверялось.** Реальное устройство, настоящий `tailscale0`, подпись дистрибутива.
