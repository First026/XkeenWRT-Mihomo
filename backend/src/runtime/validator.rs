//! Fixed standalone validator protocol and atomic incarnation-cgroup launch.
use crate::configuration::{ActivationError, Validator};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    os::fd::{AsRawFd, FromRawFd},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

pub struct ProcessValidator {
    dirty: AtomicBool,
    cgroup: Arc<File>,
}
impl ProcessValidator {
    pub fn new(cgroup: Arc<File>) -> Self {
        Self {
            dirty: AtomicBool::new(true),
            cgroup,
        }
    }
    fn memfd(name: &std::ffi::CStr) -> Result<File, ActivationError> {
        let fd = unsafe { nix::libc::memfd_create(name.as_ptr(), nix::libc::MFD_CLOEXEC) };
        if fd < 0 {
            return Err(ActivationError::Unavailable);
        }
        Ok(unsafe { File::from_raw_fd(fd) })
    }
    fn execute(
        &self, executable: &File, args: &[String], input: &[u8], purpose: xkeenwrt_recovery::VerifiedPurpose,
        timeout: Duration,
    ) -> Result<(bool, serde_json::Value), ActivationError> {
        if input.len() > 18 * 1024 * 1024 {
            return Err(ActivationError::Invalid);
        }
        let mut stdin = Self::memfd(c"xkeen-validator-input")?;
        stdin.write_all(input).map_err(|_| ActivationError::Unavailable)?;
        stdin
            .seek(SeekFrom::Start(0))
            .map_err(|_| ActivationError::Unavailable)?;
        let mut stdout = Self::memfd(c"xkeen-validator-output")?;
        let null = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/null")
            .map_err(|_| ActivationError::Unavailable)?;
        let success = xkeenwrt_recovery::run_verified_fd_in_cgroup(
            executable.as_raw_fd(),
            args,
            self.cgroup.as_raw_fd(),
            stdin.as_raw_fd(),
            stdout.as_raw_fd(),
            null.as_raw_fd(),
            purpose,
            timeout,
        )
        .map_err(|_| ActivationError::Unavailable)?;
        stdout
            .seek(SeekFrom::Start(0))
            .map_err(|_| ActivationError::Unavailable)?;
        let mut bytes = Vec::new();
        stdout
            .take(129)
            .read_to_end(&mut bytes)
            .map_err(|_| ActivationError::Unavailable)?;
        if bytes.len() > 128 {
            return Err(ActivationError::Unavailable);
        }
        let value = serde_json::from_slice(&bytes).map_err(|_| ActivationError::Unavailable)?;
        Ok((success, value))
    }
    fn cleanup(&self, executable: &File) -> Result<(), ActivationError> {
        let deadline = Instant::now() + Duration::from_secs(25);
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(ActivationError::Unavailable);
            }
            let (success, value) = self.execute(
                executable,
                &["--cleanup".into()],
                &[],
                xkeenwrt_recovery::VerifiedPurpose::ValidatorCleanup,
                remaining,
            )?;
            let code = value.get("code").and_then(|v| v.as_str());
            if success
                && value.get("status").and_then(|v| v.as_str()) == Some("clean")
                && code == Some("CLEANUP_COMPLETE")
            {
                return Ok(());
            }
            if !success && code == Some("BUSY") {
                std::thread::sleep(Duration::from_millis(100));
                continue;
            }
            return Err(ActivationError::Unavailable);
        }
    }
}
impl Validator for ProcessValidator {
    fn validate(&self, config: &str) -> Result<(), ActivationError> {
        self.validate_assets(config, &[])
    }
    fn validate_assets(&self, config: &str, assets: &[profile_policy::Asset]) -> Result<(), ActivationError> {
        self.validate_overlay(config, assets, &profile_policy::ManagedOverlay::Manual)
    }
    fn validate_overlay(
        &self, config: &str, assets: &[profile_policy::Asset], overlay: &profile_policy::ManagedOverlay,
    ) -> Result<(), ActivationError> {
        use base64::Engine;
        // Loading and policy checks precede this point; no candidate is admitted
        // without the same verified core that the isolated validator will pin.
        crate::core_update::require_validation_core()?;
        let executable = crate::platform::Platform::verified_component(
            crate::platform::VerifiedComponent::Validator,
            Some(self.cgroup.as_raw_fd()),
        )
        .ok_or(ActivationError::ValidatorUnavailable)?;
        if self.dirty.load(Ordering::Acquire) {
            self.cleanup(&executable)?;
            self.dirty.store(false, Ordering::Release);
        }
        if !profile_policy::complete_for(config, assets, overlay) {
            return Err(ActivationError::Invalid);
        }
        let assets: Vec<_> = assets.iter().map(|asset| serde_json::json!({"path":asset.path,"content_base64":base64::engine::general_purpose::STANDARD.encode(&asset.content)})).collect();
        let input =
            serde_json::to_vec(&serde_json::json!({"version":1,"config":config,"assets":assets,"overlay":overlay}))
                .map_err(|_| ActivationError::Invalid)?;
        let result = match self.execute(
            &executable,
            &[],
            &input,
            xkeenwrt_recovery::VerifiedPurpose::Validator,
            Duration::from_secs(75),
        ) {
            Ok((success, value)) => match (
                value.get("status").and_then(|v| v.as_str()),
                value.get("code").and_then(|v| v.as_str()),
            ) {
                (Some("valid"), Some("VALID")) if success => Ok(()),
                (Some("invalid"), Some("INVALID_CONFIG")) => Err(ActivationError::CoreRejected),
                _ => Err(ActivationError::ValidatorUnavailable),
            },
            _ => Err(ActivationError::ValidatorUnavailable),
        };
        if result == Err(ActivationError::ValidatorUnavailable) {
            self.dirty.store(true, Ordering::Release);
            if self.cleanup(&executable).is_ok() {
                self.dirty.store(false, Ordering::Release);
            }
        }
        result
    }
}
