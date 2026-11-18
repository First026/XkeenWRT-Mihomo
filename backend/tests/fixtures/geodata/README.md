# Синтетические DAT/MRS

Созданы `generate.go` через сериализаторы Mihomo v1.19.34: DomainSet.WriteBin, IpCidrSet.WriteBin и protobuf GeoSiteList/GeoIPList. Домены и IP относятся к тестовым диапазонам. Ни ядро Mihomo, ни сетевые службы при генерации не запускались. Go 1.25.4; zstd klauspost/compress v1.17.9. Генератор запускается внутри checkout upstream: `go run ./xkeen-fixtures /absolute/output/path`.

Проверка `official_mihomo_mrs_and_protobuf_fixtures_match_domain_and_ip_queries` читает реальные сжатые MRS и DAT, проверяет положительные и отрицательные совпадения.
