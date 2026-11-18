use std::{process::Stdio, time::Duration};

const MAX_LOG_BYTES: usize = 256 * 1024;

static CLEARED: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

fn owned_line(line: &str) -> bool {
    static TAG: std::sync::OnceLock<regex_lite::Regex> = std::sync::OnceLock::new();
    TAG.get_or_init(|| {
        regex_lite::Regex::new(r"(?:^| )xkeenwrt(?:-(?:ui|runtime|recovery|mihomo|validator|core))?(?:\[[0-9]+\])?: ")
            .expect("fixed log tag")
    })
    .is_match(line)
}

pub async fn clear() -> Result<(), &'static str> {
    let current = raw_snapshot().await?;
    *CLEARED.lock().map_err(|_| "Log cursor unavailable")? = current;
    Ok(())
}
pub async fn snapshot() -> Result<Vec<String>, &'static str> {
    let current = raw_snapshot().await?;
    let cleared = CLEARED.lock().map_err(|_| "Log cursor unavailable")?;
    let overlap = (1..=cleared.len().min(current.len()))
        .rev()
        .find(|n| cleared[cleared.len() - n..] == current[..*n])
        .unwrap_or(0);
    Ok(current[overlap..].to_vec())
}
async fn raw_snapshot() -> Result<Vec<String>, &'static str> {
    let mut output = None;
    for executable in ["/sbin/logread", "/usr/sbin/logread"] {
        let mut command = tokio::process::Command::new(executable);
        command
            .args(["-l", "200"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .env_clear()
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .env("LC_ALL", "C")
            .kill_on_drop(true);
        match tokio::time::timeout(Duration::from_secs(3), command.output()).await {
            Ok(Ok(result)) if result.status.success() => {
                output = Some(result.stdout);
                break;
            }
            Ok(Err(error)) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Ok(_) | Err(_) => return Err("OpenWrt system log is unavailable"),
        }
    }
    let bytes = output.ok_or("OpenWrt system log is unavailable")?;
    let start = bytes.len().saturating_sub(MAX_LOG_BYTES);
    let text = String::from_utf8_lossy(&bytes[start..]);
    let mut lines: Vec<String> = text
        .lines()
        .filter(|line| owned_line(line))
        .map(sanitize_line)
        .collect();
    if lines.len() > 200 {
        lines.drain(..lines.len() - 200);
    }
    Ok(lines)
}

fn sanitize_line(line: &str) -> String {
    let line: String = line.chars().take(2048).collect();
    let lower = line.to_ascii_lowercase();
    if [
        "password",
        "passwd",
        "token=",
        "secret=",
        "authorization",
        "bearer ",
        "private_key",
        "private-key",
        "uuid=",
        "vless://",
        "vmess://",
        "ss://",
        "https://",
        "http://",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
    {
        return "[sensitive system log entry redacted]".to_owned();
    }
    line.chars().filter(|ch| !ch.is_control()).collect()
}

pub fn escape_html(text: &str) -> String {
    text.chars()
        .map(|ch| match ch {
            '&' => "&amp;".to_owned(),
            '<' => "&lt;".to_owned(),
            '>' => "&gt;".to_owned(),
            '"' => "&quot;".to_owned(),
            '\'' => "&#39;".to_owned(),
            _ => ch.to_string(),
        })
        .collect()
}

pub fn html_line(line: &str) -> String {
    let lower = line.to_ascii_lowercase();
    let color = if lower.contains("error") || lower.contains("failed") || lower.contains("fatal") {
        "#ef4444"
    } else if lower.contains("warn") {
        "#f59e0b"
    } else {
        "inherit"
    };
    format!("<div style=\"color:{color}\">{}</div>", escape_html(line))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_sensitive_entries_and_escapes_log_markup() {
        assert_eq!(
            sanitize_line("service token=abcdef"),
            "[sensitive system log entry redacted]"
        );
        assert_eq!(escape_html("<tag>&"), "&lt;tag&gt;&amp;");
        assert!(html_line("<script>").contains("&lt;script&gt;"));
        assert!(owned_line("Fri daemon.err xkeenwrt-runtime[12]: failed"));
        assert!(!owned_line("Fri daemon.info dnsmasq[12]: other clients"));
    }
}
