//! Explicit, request-bound exit from the Remove fence after the same checked
//! package set has been installed again. This path never starts Mihomo.
use super::{Coordinator, RuntimeReply, upgrade_adapter::NativeUpgradeAdapter};
use std::{fs::File, os::fd::AsRawFd, os::unix::fs::MetadataExt, path::Path};

const DATA: &str = "/etc/xkeenwrt";
const MUTATION_LOCK: &str = "/var/run/xkeenwrt/mutation.lock";

struct ResumeSnapshot {
    owner: String,
    package_helper: File,
    persistent_helper: File,
    helper_sha256: String,
    helper_build_id: &'static str,
}

#[derive(Clone, Copy)]
enum Failure {
    InvalidRequest,
    Conflict,
    PackageMismatch,
    RescueVersionMismatch,
    NotReady,
    CommitUncertain,
}

impl Failure {
    fn reply(self) -> RuntimeReply {
        match self {
            Self::InvalidRequest => RuntimeReply::error("INVALID", "Invalid Remove request identity"),
            Self::Conflict => RuntimeReply::error("CONFLICT", "Remove request or lifecycle state changed"),
            Self::PackageMismatch => {
                RuntimeReply::error("PACKAGE_MISMATCH", "Installed packages do not match this build")
            }
            Self::RescueVersionMismatch => RuntimeReply::error(
                "RESCUE_VERSION_MISMATCH",
                "Persistent rescue requires a coordinated replacement",
            ),
            Self::NotReady => RuntimeReply::error("NOT_READY", "Resume safety proof is unavailable"),
            Self::CommitUncertain => RuntimeReply::error("COMMIT_UNCERTAIN", "Recheck lifecycle state before retrying"),
        }
    }
}

pub(super) fn completed_request_id() -> std::io::Result<Option<String>> {
    let owner = read_owner()?;
    xkeenwrt_recovery::completed_remove_request_id(Path::new(DATA), &owner)
}

fn read_owner() -> std::io::Result<String> {
    let bytes = super::upgrade_adapter::private(&Path::new(DATA).join("owner-id"), 128)?;
    let owner = std::str::from_utf8(&bytes).map_err(std::io::Error::other)?;
    let parsed = uuid::Uuid::parse_str(owner).map_err(std::io::Error::other)?;
    if parsed.to_string() != owner {
        return Err(std::io::Error::other("invalid owner identity"));
    }
    Ok(owner.to_owned())
}

fn persistent_identity() -> Result<(String, String), Failure> {
    let bytes = super::upgrade_adapter::private(&Path::new(DATA).join("rescue/identity"), 256)
        .map_err(|_| Failure::NotReady)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| Failure::NotReady)?;
    let mut lines = text.lines();
    if lines.next() != Some("xkeenwrt-rescue-v1") {
        return Err(Failure::NotReady);
    }
    let build_id = lines
        .next()
        .and_then(|line| line.strip_prefix("build_id="))
        .ok_or(Failure::NotReady)?
        .to_owned();
    let digest = lines
        .next()
        .and_then(|line| line.strip_prefix("sha256="))
        .ok_or(Failure::NotReady)?
        .to_owned();
    let valid_digest =
        |value: &str| value.len() == 64 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if lines.next().is_some()
        || !valid_digest(&build_id)
        || !valid_digest(&digest)
        || text != format!("xkeenwrt-rescue-v1\nbuild_id={build_id}\nsha256={digest}\n")
    {
        return Err(Failure::NotReady);
    }
    Ok((digest, build_id))
}

fn replacement_absent() -> bool {
    xkeenwrt_recovery::rescue::upgrade_status().is_ok_and(|intent| intent.is_none())
        && [
            Path::new(DATA).join("lifecycle.json"),
            Path::new(DATA).join(".rescue-next"),
        ]
        .iter()
        .all(|path| matches!(std::fs::symlink_metadata(path), Err(error) if error.kind() == std::io::ErrorKind::NotFound))
}

fn snapshot(coordinator: &Coordinator, request_id: &str) -> Result<ResumeSnapshot, Failure> {
    if !super::core::deployment_allowed() {
        return Err(Failure::NotReady);
    }
    let owner = read_owner().map_err(|_| Failure::NotReady)?;
    match xkeenwrt_recovery::completed_remove_request_id(Path::new(DATA), &owner).map_err(|_| Failure::NotReady)? {
        Some(current) if current == request_id => (),
        _ => return Err(Failure::Conflict),
    }
    if !crate::platform::Platform::compatible_packages_in(Some(coordinator.incarnation_cgroup.as_raw_fd())) {
        return Err(Failure::PackageMismatch);
    }
    let Some((package_helper, helper_sha256, helper_build_id)) =
        crate::platform::Platform::verified_recovery(coordinator.incarnation_cgroup.as_raw_fd())
    else {
        return Err(Failure::PackageMismatch);
    };
    let (persistent_sha256, persistent_build_id) = persistent_identity()?;
    if persistent_sha256 != helper_sha256 || persistent_build_id != helper_build_id {
        return Err(Failure::RescueVersionMismatch);
    }
    let persistent_helper =
        xkeenwrt_recovery::rescue::verify(&persistent_sha256, &persistent_build_id).map_err(|_| Failure::NotReady)?;
    if !replacement_absent() {
        return Err(Failure::Conflict);
    }
    let adapter = NativeUpgradeAdapter {
        incarnation: &coordinator.incarnation_cgroup,
        identity: &coordinator.incarnation_identity,
    };
    adapter
        .verify_remove_resume_quiescent(&owner, request_id)
        .map_err(|_| Failure::NotReady)?;
    Ok(ResumeSnapshot {
        owner,
        package_helper,
        persistent_helper,
        helper_sha256,
        helper_build_id,
    })
}

fn same_file(left: &File, right: &File) -> std::io::Result<bool> {
    let left = left.metadata()?;
    let right = right.metadata()?;
    Ok(left.dev() == right.dev() && left.ino() == right.ino())
}

fn resume(coordinator: &mut Coordinator, request_id: &str) -> Result<(), Failure> {
    let Ok(parsed_request_id) = uuid::Uuid::parse_str(request_id) else {
        return Err(Failure::InvalidRequest);
    };
    if parsed_request_id.to_string() != request_id {
        return Err(Failure::InvalidRequest);
    }
    let mut mutation_lock =
        Some(super::ipc::RuntimeLock::acquire(Path::new(MUTATION_LOCK)).map_err(|_| Failure::NotReady)?);
    let before = snapshot(coordinator, request_id)?;
    let adapter = NativeUpgradeAdapter {
        incarnation: &coordinator.incarnation_cgroup,
        identity: &coordinator.incarnation_identity,
    };
    drop(mutation_lock.take());
    adapter
        .wait_remove_resume_ready(
            &before.owner,
            request_id,
            &before.package_helper,
            &before.persistent_helper,
            &before.helper_sha256,
            before.helper_build_id,
        )
        .map_err(|_| Failure::NotReady)?;
    mutation_lock = Some(super::ipc::RuntimeLock::acquire(Path::new(MUTATION_LOCK)).map_err(|_| Failure::NotReady)?);
    let after = snapshot(coordinator, request_id)?;
    if before.owner != after.owner
        || before.helper_sha256 != after.helper_sha256
        || before.helper_build_id != after.helper_build_id
        || !same_file(&before.package_helper, &after.package_helper).map_err(|_| Failure::NotReady)?
        || !same_file(&before.persistent_helper, &after.persistent_helper).map_err(|_| Failure::NotReady)?
    {
        return Err(Failure::Conflict);
    }
    let adapter = NativeUpgradeAdapter {
        incarnation: &coordinator.incarnation_cgroup,
        identity: &coordinator.incarnation_identity,
    };
    adapter
        .verify_remove_resume_ready(
            &after.owner,
            request_id,
            &after.package_helper,
            &after.persistent_helper,
            &after.helper_sha256,
            after.helper_build_id,
        )
        .map_err(|_| Failure::NotReady)?;

    coordinator
        .activation
        .settle_stopped_manual(Path::new(DATA))
        .map_err(|_| Failure::NotReady)?;
    super::grant::ensure_core_cgroup().map_err(|_| Failure::NotReady)?;
    if xkeenwrt_recovery::finish_remove_after_integrity_check(Path::new(DATA), &after.owner, request_id).is_err() {
        match xkeenwrt_recovery::completed_remove_request_id(Path::new(DATA), &after.owner) {
            Ok(Some(current)) if current == request_id => return Err(Failure::NotReady),
            _ => return Err(Failure::CommitUncertain),
        }
    }
    drop(mutation_lock);
    coordinator.ready = true;
    Ok(())
}

pub(super) fn resume_after_reinstall(coordinator: &mut Coordinator, request_id: &str) -> RuntimeReply {
    match resume(coordinator, request_id) {
        Ok(()) => {
            let mut reply = RuntimeReply::error("OK", "resumed_stopped");
            reply.running = Some(false);
            reply
        }
        Err(failure) => failure.reply(),
    }
}
