#[derive(Clone, Copy)]
pub enum Scenario {
    Probe,
    Timeout,
    Output,
    Tmpfs,
    Pids,
    Memory,
    SetupDenied,
    MihomoValid,
    MihomoInvalid,
    MihomoInvalidUnreadable,
    MihomoMissingAsset,
    MihomoFileContained,
    MihomoFileEscape,
    MihomoAwgV3,
    MihomoAwgLegacy,
}

impl Scenario {
    pub fn is_core(self) -> bool {
        matches!(
            self,
            Self::MihomoValid
                | Self::MihomoInvalid
                | Self::MihomoInvalidUnreadable
                | Self::MihomoMissingAsset
                | Self::MihomoFileContained
                | Self::MihomoFileEscape
                | Self::MihomoAwgV3
                | Self::MihomoAwgLegacy
        )
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::Probe => "probe",
            Self::Timeout => "timeout",
            Self::Output => "output",
            Self::Tmpfs => "tmpfs",
            Self::Pids => "pids",
            Self::Memory => "memory",
            Self::SetupDenied => "setup-denied",
            Self::MihomoValid => "mihomo-valid",
            Self::MihomoInvalid => "mihomo-invalid",
            Self::MihomoInvalidUnreadable => "mihomo-invalid-unreadable",
            Self::MihomoMissingAsset => "mihomo-missing-asset",
            Self::MihomoFileContained => "mihomo-file-contained",
            Self::MihomoFileEscape => "mihomo-file-escape",
            Self::MihomoAwgV3 => "mihomo-awg-v3",
            Self::MihomoAwgLegacy => "mihomo-awg-legacy",
        }
    }
}

pub struct ChildFds {
    pub ready: libc::c_int,
    pub exec_error: libc::c_int,
    pub status: libc::c_int,
}
