//! Disposable, fixed-scenario VM experiment; not a production validator.
mod child;
mod preflight;
mod protocol;
mod supervisor;

use protocol::Scenario;

fn main() {
    let mut args = std::env::args_os();
    let _program = args.next();
    let scenario = match args.next().as_deref().and_then(|s| s.to_str()) {
        Some("probe") => Some(Scenario::Probe),
        Some("timeout") => Some(Scenario::Timeout),
        Some("output") => Some(Scenario::Output),
        Some("tmpfs") => Some(Scenario::Tmpfs),
        Some("pids") => Some(Scenario::Pids),
        Some("memory") => Some(Scenario::Memory),
        Some("setup-denied") => Some(Scenario::SetupDenied),
        Some("mihomo-valid") => Some(Scenario::MihomoValid),
        Some("mihomo-invalid") => Some(Scenario::MihomoInvalid),
        Some("mihomo-invalid-unreadable") => Some(Scenario::MihomoInvalidUnreadable),
        Some("mihomo-missing-asset") => Some(Scenario::MihomoMissingAsset),
        Some("mihomo-file-contained") => Some(Scenario::MihomoFileContained),
        Some("mihomo-file-escape") => Some(Scenario::MihomoFileEscape),
        Some("mihomo-awg-v3") => Some(Scenario::MihomoAwgV3),
        Some("mihomo-awg-legacy") => Some(Scenario::MihomoAwgLegacy),
        _ => None,
    }
    .filter(|_| args.next().is_none());
    if let Some(scenario) = scenario {
        if preflight::marked_guest() {
            match supervisor::run(scenario) {
                Ok(Some(peak)) => {
                    println!(
                        "{{\"scenario\":\"{}\",\"result\":\"pass\",\"memory_peak_bytes\":{peak}}}",
                        scenario.name()
                    );
                    return;
                }
                Ok(None) => {
                    println!(
                        "{{\"scenario\":\"{}\",\"result\":\"pass\"}}",
                        scenario.name()
                    );
                    return;
                }
                Err(reason) => {
                    println!(
                        "{{\"scenario\":\"{}\",\"result\":\"unavailable\",\"reason\":\"{}\"}}",
                        scenario.name(),
                        reason
                    );
                    std::process::exit(1);
                }
            }
        }
    }
    println!(
        "{{\"scenario\":\"{}\",\"result\":\"unavailable\"}}",
        scenario.map(Scenario::name).unwrap_or("unknown")
    );
    std::process::exit(1);
}
