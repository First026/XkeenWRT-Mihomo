//! Read-only explanations of saved profiles. Unknown predicates never become a
//! fabricated successful route; no packets, DNS configuration or rules are changed.
use crate::rule_resources::{cidr_matches, domain_pattern, suffix};
use serde::Deserialize;
use serde_json::{Value, json};
use std::net::IpAddr;
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RouteRequest {
    pub profile_id: String,
    pub expected_revision: String,
    pub targets: Vec<String>,
    pub port: u16,
    pub network: String,
    pub source_ip: Option<IpAddr>,
    pub inbound_tag: Option<String>,
}
fn normalized(raw: &str) -> Result<String, &'static str> {
    let target = raw.trim();
    if target.len() > 2048 {
        return Err("Слишком длинная цель");
    }
    if target.parse::<IpAddr>().is_ok() {
        return Ok(target.to_owned());
    }
    let url = reqwest::Url::parse(&format!(
        "https://{}",
        target.split_once("://").map_or(target, |(_, s)| s)
    ))
    .map_err(|_| "Некорректная цель")?;
    let host = url
        .host_str()
        .ok_or("Некорректная цель")?
        .trim_matches(['[', ']'])
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if host.len() > 253 || host.is_empty() {
        return Err("Некорректная цель");
    }
    Ok(host)
}
fn port_match(port: u16, pattern: &str) -> Result<bool, &'static str> {
    let mut matched = false;
    for part in pattern.split('/') {
        let (lo, hi) = part.split_once('-').unwrap_or((part, part));
        let lo = lo.parse::<u16>().map_err(|_| "Некорректный диапазон порта")?;
        let hi = hi.parse::<u16>().map_err(|_| "Некорректный диапазон порта")?;
        if lo > hi {
            return Err("Некорректный диапазон порта");
        }
        matched |= (lo..=hi).contains(&port);
    }
    Ok(matched)
}
fn predicate(kind: &str, value: &str, target: &str, request: &RouteRequest, doc: &Value) -> Result<bool, &'static str> {
    match kind {
        "MATCH" => Ok(true),
        "DOMAIN" => Ok(target.eq_ignore_ascii_case(value)),
        "DOMAIN-SUFFIX" => Ok(suffix(target, &value.to_ascii_lowercase())),
        "DOMAIN-KEYWORD" => Ok(target.contains(&value.to_ascii_lowercase())),
        "DOMAIN-REGEX" if value.len() <= 2048 => regex_lite::Regex::new(value)
            .map(|re| re.is_match(target))
            .map_err(|_| "Ошибка регулярного выражения"),
        "IP-CIDR" | "IP-CIDR6" => cidr_matches(
            target
                .parse()
                .map_err(|_| "Для IP-правила нужен IP; DNS/sniffing в этом просмотре не выполняются")?,
            value,
        ),
        "SRC-IP-CIDR" | "SRC-IP-CIDR6" => cidr_matches(request.source_ip.ok_or("Не указан IP клиента")?, value),
        "DST-PORT" => port_match(request.port, value),
        "NETWORK" => Ok(request.network.eq_ignore_ascii_case(value)),
        "IN-NAME" | "IN-TAG" => Ok(request.inbound_tag.as_deref() == Some(value)),
        "RULE-SET" => {
            let provider = &doc["rule-providers"][value];
            let behavior = provider["behavior"].as_str().ok_or("Неизвестный провайдер правил")?;
            let lines = if let Some(payload) = provider["payload"].as_array() {
                payload
                    .iter()
                    .map(|s| s.as_str().map(str::to_owned).ok_or("Некорректный payload"))
                    .collect::<Result<Vec<_>, _>>()?
            } else {
                if provider["type"].as_str() != Some("file") {
                    return Err(
                        "Удалённый RULE-SET: требуется сохранённая локальная копия; новый запрос не выполняется",
                    );
                }
                let file = provider["path"]
                    .as_str()
                    .and_then(|p| p.strip_prefix("resources/"))
                    .ok_or("Провайдер вне разрешённого каталога профиля")?;
                let bytes = crate::resources::read(&request.profile_id, file)?;
                match provider["format"].as_str().unwrap_or("yaml") {
                    "mrs" => {
                        let mrs = crate::rule_resources::read_mrs(&bytes)?;
                        if mrs.behavior != behavior {
                            return Err("Behavior MRS не совпадает с профилем");
                        }
                        mrs.rules
                    }
                    "text" => std::str::from_utf8(&bytes)
                        .map_err(|_| "Некорректный текст провайдера")?
                        .lines()
                        .map(str::trim)
                        .filter(|line| !line.is_empty() && !line.starts_with('#'))
                        .map(str::to_owned)
                        .collect(),
                    "yaml" => {
                        profile_policy::parse_document(std::str::from_utf8(&bytes).map_err(|_| "Некорректный YAML")?)
                            .map_err(|_| "Некорректный YAML")?["payload"]
                            .as_array()
                            .ok_or("Нет payload")?
                            .iter()
                            .map(|s| s.as_str().map(str::to_owned).ok_or("Некорректный payload"))
                            .collect::<Result<Vec<_>, _>>()?
                    }
                    _ => return Err("Формат провайдера не поддерживается"),
                }
            };
            if lines.len() > 100_000 {
                return Err("Слишком большой набор правил для интерактивной проверки");
            }
            for line in lines {
                let matched = match behavior {
                    "domain" => domain_pattern(target, &line),
                    "ipcidr" => cidr_matches(target.parse().map_err(|_| "Укажите IP для IP-CIDR провайдера")?, &line)?,
                    "classical" => {
                        let mut parts = line.split(',').map(str::trim);
                        let kind = parts.next().ok_or("Некорректное правило")?;
                        if matches!(kind, "RULE-SET" | "GEOSITE" | "GEOIP") {
                            return Err("Вложенные геоправила в classical пока не поддерживаются");
                        }
                        predicate(kind, parts.next().unwrap_or(""), target, request, doc)?
                    }
                    _ => return Err("Неизвестный behavior"),
                };
                if matched {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        "GEOIP" | "GEOSITE" => {
            let ip_mode = kind == "GEOIP";
            if value.contains('@') || value.contains(':') {
                return Err("Атрибуты и внешние теги DAT пока не поддерживаются");
            }
            let resources = crate::resources::list(&request.profile_id)?;
            let prefix = if ip_mode { "geoip" } else { "geosite" };
            let candidates: Vec<_> = resources
                .iter()
                .filter(|r| r.format == "dat" && r.id.to_ascii_lowercase().starts_with(prefix))
                .collect();
            if candidates.len() != 1 {
                return Err("Нужен один принадлежащий профилю GeoSite/GeoIP DAT");
            }
            let bytes = crate::resources::read(&request.profile_id, &candidates[0].id)?;
            Ok(crate::rule_resources::dat_categories(&bytes, target, ip_mode)?
                .iter()
                .any(|c| c.eq_ignore_ascii_case(value)))
        }
        _ => Err("Это правило зависит от неподдерживаемого алгоритма или runtime-метаданных; результат не определён"),
    }
}
pub fn routes(source: &str, request: &RouteRequest) -> Result<Value, &'static str> {
    if request.targets.is_empty()
        || request.targets.len() > 500
        || !matches!(request.network.as_str(), "tcp" | "udp")
        || request.port == 0
    {
        return Err("Некорректные параметры проверки");
    }
    let doc = profile_policy::parse_document(source).map_err(|_| "Некорректный профиль")?;
    let rules = doc["rules"].as_array().ok_or("В профиле нет rules")?;
    if rules.len().saturating_mul(request.targets.len()) > 250_000 {
        return Err("Слишком много правил и целей для одной проверки");
    }
    let mut results = Vec::new();
    for raw in &request.targets {
        let target = match normalized(raw) {
            Ok(target) => target,
            Err(error) => {
                results.push(json!({"target":raw,"kind":"domain","outcome":"error","outbound":null,"rule":null,"balancer":null,"resolvedIps":[],"dnsSource":null,"skipped":[],"error":error}));
                continue;
            }
        };
        let mut result = json!({"target":target,"kind":if target.parse::<IpAddr>().is_ok(){"ip"}else{"domain"},"outcome":"default","outbound":"DIRECT","rule":null,"balancer":null,"resolvedIps":[],"dnsSource":null,"skipped":[],"error":null});
        for (index, rule) in rules.iter().enumerate() {
            let Some(text) = rule.as_str() else {
                return Err("Некорректный список rules");
            };
            let parts: Vec<_> = text.split(',').map(str::trim).collect();
            let kind = parts.first().copied().unwrap_or("");
            let (value, outbound) = if kind == "MATCH" {
                ("", parts.get(1).copied())
            } else {
                (parts.get(1).copied().unwrap_or(""), parts.get(2).copied())
            };
            let Some(outbound) = outbound else {
                return Err("Правило не содержит группу/исход");
            };
            match predicate(kind, value, &target, request, &doc) {
                Ok(false) => (),
                Ok(true) => {
                    result["outcome"] = json!("matched");
                    result["outbound"] = json!(outbound);
                    result["rule"] =
                        json!({"index":index+1,"text":text,"detail":"Сохранённый профиль; без изменения сети"});
                    break;
                }
                Err(reason) => {
                    result["outcome"] = json!("error");
                    result["outbound"] = Value::Null;
                    result["skipped"] = json!([{"index":index+1,"text":text,"reason":reason}]);
                    result["error"] = json!(reason);
                    break;
                }
            }
        }
        results.push(result);
    }
    Ok(
        json!({"success":true,"core":"mihomo","results":results,"warnings":["Проверяется сохранённый профиль. DNS, sniffing, процессные правила и состояние соединения не моделируются; неподдерживаемый предикат делает исход неопределённым."]}),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    fn request(target: &str) -> RouteRequest {
        RouteRequest {
            profile_id: "config".into(),
            expected_revision: "revision".into(),
            targets: vec![target.into()],
            port: 443,
            network: "tcp".into(),
            source_ip: None,
            inbound_tag: None,
        }
    }
    #[test]
    fn unknown_prior_rule_cannot_silently_fall_through_to_direct() {
        let result = routes("rules: [PROCESS-NAME, MATCH,DIRECT]", &request("example.com"));
        assert!(result.is_err());
        let result = routes(
            "rules:\n  - PROCESS-NAME,app,Proxy\n  - MATCH,DIRECT",
            &request("example.com"),
        )
        .unwrap();
        assert_eq!(result["results"][0]["outcome"], "error");
        assert!(result["results"][0]["outbound"].is_null());
    }
    #[test]
    fn suffix_and_transport_match_in_rule_order() {
        let source = "rules:\n  - DOMAIN-SUFFIX,example.com,Proxy\n  - NETWORK,udp,REJECT\n  - MATCH,DIRECT";
        assert_eq!(
            routes(source, &request("https://cdn.example.com/a")).unwrap()["results"][0]["outbound"],
            "Proxy"
        );
        assert_eq!(
            routes(source, &request("notexample.com")).unwrap()["results"][0]["outbound"],
            "DIRECT"
        );
        let mut r = request("notexample.com");
        r.network = "udp".into();
        assert_eq!(routes(source, &r).unwrap()["results"][0]["outbound"], "REJECT");
    }
}
