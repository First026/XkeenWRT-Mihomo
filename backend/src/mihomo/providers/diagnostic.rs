//! Fixed public diagnostics. No error ever contains a URL, body, header or node URI.
use super::ProviderError;
use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    InvalidUrl,
    AddressForbidden,
    Dns,
    Timeout,
    Transport,
    HttpStatus,
    RedirectInvalid,
    RedirectForbidden,
    RedirectLoop,
    RedirectLimit,
    TooLarge,
    SubscriptionEmpty,
    SubscriptionFormat,
    SubscriptionUnsupported,
    RuleFormat,
    RuleBehavior,
    MrsLimit,
    Policy,
    CoreRejected,
    ValidatorUnavailable,
    CoreMissing,
    CoreIntegrity,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Diagnostic {
    pub reason: Reason,
    pub provider: Option<String>,
    pub http_status: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub import: Option<crate::mihomo::subscription::ImportDetail>,
}
impl Diagnostic {
    pub fn new(reason: Reason) -> Self {
        Self {
            reason,
            provider: None,
            http_status: None,
            import: None,
        }
    }
    pub fn stage(&self) -> &'static str {
        use Reason::*;
        match self.reason {
            SubscriptionEmpty | SubscriptionFormat | SubscriptionUnsupported => "subscription",
            RuleFormat | RuleBehavior | MrsLimit => "ruleset",
            Policy => "policy",
            CoreRejected | ValidatorUnavailable | CoreMissing | CoreIntegrity => "core_validation",
            _ => "download",
        }
    }
    pub fn message(&self) -> String {
        use Reason::*;
        let cause = match self.reason {
            InvalidUrl => "недопустимый адрес источника",
            AddressForbidden => "источник разрешается в запрещённый адрес",
            Dns => "не удалось разрешить DNS источника",
            Timeout => "истёк срок загрузки",
            Transport => "ошибка соединения или TLS",
            HttpStatus => "источник вернул ошибку HTTP",
            RedirectInvalid => "некорректный адрес перенаправления",
            RedirectForbidden => "небезопасное перенаправление запрещено",
            RedirectLoop => "цикл перенаправлений",
            RedirectLimit => "превышено число перенаправлений",
            TooLarge => "превышен лимит размера ответа (2 MiB) или набора (8 MiB)",
            SubscriptionEmpty => "подписка пуста",
            SubscriptionFormat => "ожидался YAML с proxies, список URI или его Base64",
            SubscriptionUnsupported => "подписка содержит неподдерживаемый узел или параметр; ни один узел не отброшен",
            RuleFormat => "неверный или неподдерживаемый формат рулсета",
            RuleBehavior => "тип MRS не соответствует behavior",
            MrsLimit => "MRS превышает бюджет распаковки или окна 16 MiB",
            Policy => "содержимое не прошло проверку разрешённых параметров",
            CoreRejected => "Mihomo отклонил подготовленный профиль",
            ValidatorUnavailable => "изолированный валидатор не смог завершить проверку ядром",
            CoreMissing => {
                "Mihomo не установлен; проверка ядром не выполнялась. Откройте «Mihomo → Установить» в верхней панели"
            }
            CoreIntegrity => "целостность установленного Mihomo не подтверждена; откройте управление ядром",
        };
        let stage = match self.stage() {
            "subscription" => "Разбор подписки",
            "ruleset" => "Проверка рулсета",
            "policy" => "Проверка профиля",
            "core_validation" => "Проверка ядром",
            _ => "Загрузка провайдера",
        };
        // IDs are generated internally. Also reject malformed IPC diagnostics rather than echoing them.
        let provider = self.provider.as_deref().filter(|s| {
            s.len() <= 16
                && s.split_once('-').is_some_and(|(p, n)| {
                    matches!(p, "proxy" | "rule") && !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit())
                })
        });
        let detail = self
            .import
            .filter(|d| (1..=2048).contains(&d.node))
            .map(|d| {
                format!(
                    "; узел {}, {}{}",
                    d.node,
                    d.parameter.label(),
                    d.position
                        .filter(|p| (1..=16384).contains(p))
                        .map(|p| format!(", позиция {p} в URI query"))
                        .unwrap_or_default()
                )
            })
            .unwrap_or_default();
        format!(
            "{stage}{}: {cause}{}{detail}.",
            provider.map(|p| format!(" ({p})")).unwrap_or_default(),
            self.http_status
                .filter(|n| (100..600).contains(n))
                .map(|n| format!(" ({n})"))
                .unwrap_or_default()
        )
    }
}
impl From<crate::mihomo::subscription::ImportError> for ProviderError {
    fn from(error: crate::mihomo::subscription::ImportError) -> Self {
        use crate::mihomo::subscription::ImportError::*;
        let mut d = Diagnostic::new(match error {
            Empty => Reason::SubscriptionEmpty,
            Format => Reason::SubscriptionFormat,
            TooLarge => Reason::TooLarge,
            Unsupported | Parameter(_) => Reason::SubscriptionUnsupported,
        });
        if let Parameter(detail) = error {
            d.import = Some(detail);
        }
        Self::Detailed(d)
    }
}
impl ProviderError {
    pub fn failure(reason: Reason) -> Self {
        Self::Detailed(Diagnostic::new(reason))
    }
    pub fn diagnostic(self) -> Diagnostic {
        match self {
            Self::Detailed(d) => d,
            Self::TooLarge => Diagnostic::new(Reason::TooLarge),
            Self::Network => Diagnostic::new(Reason::Timeout),
            _ => Diagnostic::new(Reason::Policy),
        }
    }
    pub fn at(self, id: &str) -> Self {
        let mut d = self.diagnostic();
        d.provider = Some(id.into());
        Self::Detailed(d)
    }
}
