//! Resource admission with a forecast: every shortage names its resource and
//! carries numbers, never paths or YAML. Laboratory limits from decision 009.
use crate::configuration::ActivationError;
use serde::Serialize;
use std::{io::Read, path::Path};
use xkeenwrt_recovery::resources::{HistoryFull, HistoryNeed};
const MIB: u64 = 1024 * 1024;
const MEMORY_FLOOR: u64 = 256 * MIB;
const SPACE_FLOOR: u64 = 32 * MIB;

/// Fresh readings for one admission. `memory_reclaimable` is the memory of
/// this project's own running core when the operation replaces it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Measured {
    pub memory_available: u64,
    pub memory_reclaimable: u64,
    pub tmp_free: u64,
    pub tmp_block: u64,
    pub flash_free: u64,
    pub flash_block: u64,
}
/// What reserving the operation's history would do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HistoryOutlook {
    /// Fits, possibly after removing this many unpinned entries first.
    Fits { cleanup_entries: usize },
    /// Does not fit even after removing everything unpinned.
    Full(HistoryFull),
    /// History could not be inspected safely.
    Unknown,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "resource", rename_all = "snake_case")]
pub enum Shortage {
    Memory {
        available_mib: u64,
        reclaimable_mib: u64,
        required_mib: u64,
    },
    Tmp {
        available_mib: u64,
        required_mib: u64,
    },
    Flash {
        available_mib: u64,
        required_mib: u64,
    },
    History {
        used_entries: usize,
        limit_entries: usize,
        needed_entries: usize,
        reclaimable_entries: usize,
        used_mib: u64,
        limit_mib: u64,
        needed_mib: u64,
        reclaimable_mib: u64,
    },
}
impl Shortage {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Memory { .. } => "NETWORK_MEMORY",
            Self::Tmp { .. } => "NETWORK_TMP",
            Self::Flash { .. } => "NETWORK_FLASH",
            Self::History { .. } => "NETWORK_HISTORY",
        }
    }
}
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Forecast {
    pub shortages: Vec<Shortage>,
    /// Unpinned history entries the operation will remove before writing.
    pub cleanup_entries: usize,
    /// A reading failed: admission is refused without numbers.
    pub unavailable: bool,
}
impl Forecast {
    pub fn admitted(&self) -> bool {
        !self.unavailable && self.shortages.is_empty()
    }
    fn unavailable() -> Self {
        Self {
            unavailable: true,
            ..Self::default()
        }
    }
}
fn floor_mib(bytes: u64) -> u64 {
    bytes / MIB
}
fn ceil_mib(bytes: u64) -> u64 {
    bytes.div_ceil(MIB)
}
/// Pure admission over fresh readings. A bundle of at most 33 files is staged
/// twice in `/tmp`; flash staging is at most three journal-path files.
pub(crate) fn evaluate(m: &Measured, bundle: u64, staging: u64, history: HistoryOutlook) -> Forecast {
    let mut forecast = Forecast::default();
    let memory = m.memory_available.saturating_add(m.memory_reclaimable);
    if memory < MEMORY_FLOOR {
        forecast.shortages.push(Shortage::Memory {
            available_mib: floor_mib(m.memory_available),
            reclaimable_mib: floor_mib(m.memory_reclaimable),
            required_mib: ceil_mib(MEMORY_FLOOR),
        });
    }
    let allocated_bundle = if bundle == 0 {
        0
    } else {
        bundle.saturating_add(m.tmp_block.saturating_sub(1).saturating_mul(33))
    };
    let tmp_required = SPACE_FLOOR.saturating_add(allocated_bundle.saturating_mul(2));
    if m.tmp_free < tmp_required {
        forecast.shortages.push(Shortage::Tmp {
            available_mib: floor_mib(m.tmp_free),
            required_mib: ceil_mib(tmp_required),
        });
    }
    let allocated_staging = if staging == 0 {
        0
    } else {
        staging.saturating_add(m.flash_block.saturating_sub(1).saturating_mul(35))
    };
    let flash_required = SPACE_FLOOR.saturating_add(allocated_staging);
    if m.flash_free < flash_required {
        forecast.shortages.push(Shortage::Flash {
            available_mib: floor_mib(m.flash_free),
            required_mib: ceil_mib(flash_required),
        });
    }
    match history {
        HistoryOutlook::Fits { cleanup_entries } => forecast.cleanup_entries = cleanup_entries,
        HistoryOutlook::Full(full) => forecast.shortages.push(Shortage::History {
            used_entries: full.used_entries,
            limit_entries: full.limit_entries,
            needed_entries: full.needed_entries,
            reclaimable_entries: full.reclaimable_entries,
            used_mib: ceil_mib(full.used_bytes),
            limit_mib: floor_mib(full.limit_bytes),
            needed_mib: ceil_mib(full.needed_bytes),
            reclaimable_mib: floor_mib(full.reclaimable_bytes),
        }),
        HistoryOutlook::Unknown => forecast.unavailable = true,
    }
    forecast
}
fn free(path: &Path) -> Result<(u64, u64), ActivationError> {
    let dir = std::fs::File::open(path).map_err(|_| ActivationError::Storage)?;
    let stat = rustix::fs::fstatvfs(&dir).map_err(|_| ActivationError::Storage)?;
    if stat.f_frsize == 0 {
        return Err(ActivationError::Storage);
    }
    Ok((stat.f_bavail.saturating_mul(stat.f_frsize), stat.f_frsize))
}
fn measure(memory_reclaimable: u64) -> Result<Measured, ActivationError> {
    let mut text = String::new();
    std::fs::File::open("/proc/meminfo")
        .map_err(|_| ActivationError::Unavailable)?
        .take(65537)
        .read_to_string(&mut text)
        .map_err(|_| ActivationError::Unavailable)?;
    if text.len() > 65536 {
        return Err(ActivationError::Unavailable);
    }
    let memory_available = text
        .lines()
        .find_map(|line| {
            let value = line.strip_prefix("MemAvailable:")?.trim();
            let number = value.strip_suffix(" kB")?.trim().parse::<u64>().ok()?;
            number.checked_mul(1024)
        })
        .ok_or(ActivationError::Unavailable)?;
    let (tmp_free, tmp_block) = free(Path::new("/tmp"))?;
    let (flash_free, flash_block) = free(Path::new("/etc/xkeenwrt"))?;
    Ok(Measured {
        memory_available,
        memory_reclaimable,
        tmp_free,
        tmp_block,
        flash_free,
        flash_block,
    })
}
fn outlook(need: &HistoryNeed) -> HistoryOutlook {
    match xkeenwrt_recovery::resources::plan_history_append(Path::new("/etc/xkeenwrt"), need, &Default::default()) {
        Ok(plan) => HistoryOutlook::Fits {
            cleanup_entries: plan.freed_entries,
        },
        Err(error) => {
            xkeenwrt_recovery::resources::history_full(&error).map_or(HistoryOutlook::Unknown, HistoryOutlook::Full)
        }
    }
}
/// Read-only forecast for an operation: nothing is removed or written.
pub(crate) fn forecast(bundle: u64, staging: u64, memory_reclaimable: u64, need: &HistoryNeed) -> Forecast {
    match measure(memory_reclaimable) {
        Ok(measured) => evaluate(&measured, bundle, staging, outlook(need)),
        Err(_) => Forecast::unavailable(),
    }
}
/// Admit an operation that writes no history beyond its own reservation.
/// `memory_reclaimable` must be zero unless the operation replaces this
/// project's verified running core.
pub(super) fn admit(bundle: u64, staging: u64, memory_reclaimable: u64) -> Result<(), ActivationError> {
    if forecast(bundle, staging, memory_reclaimable, &HistoryNeed::default()).admitted() {
        Ok(())
    } else {
        Err(ActivationError::Unavailable)
    }
}
/// Make room once, before an operation's first write, for all the history it
/// will append. Later writers of the same operation only check that they fit.
pub(crate) fn reserve_history(
    need: &xkeenwrt_recovery::resources::HistoryNeed, protect: &std::collections::BTreeSet<String>,
) -> Result<(), ActivationError> {
    xkeenwrt_recovery::resources::reserve_history(Path::new("/etc/xkeenwrt"), need, protect)
        .map(|_| ())
        .map_err(|_| ActivationError::Storage)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn measured(memory_mib: u64, reclaimable_mib: u64) -> Measured {
        Measured {
            memory_available: memory_mib * MIB,
            memory_reclaimable: reclaimable_mib * MIB,
            tmp_free: 64 * MIB,
            tmp_block: 4096,
            flash_free: 64 * MIB,
            flash_block: 4096,
        }
    }
    fn fits() -> HistoryOutlook {
        HistoryOutlook::Fits { cleanup_entries: 0 }
    }
    #[test]
    fn memory_counts_the_core_this_operation_replaces() {
        // A working router on 17.11: 243 MiB available while the running Mihomo held 74 MiB.
        assert!(evaluate(&measured(243, 74), MIB, MIB, fits()).admitted());
        let forecast = evaluate(&measured(243, 0), MIB, MIB, fits());
        assert!(!forecast.admitted());
        assert_eq!(
            forecast.shortages,
            vec![Shortage::Memory {
                available_mib: 243,
                reclaimable_mib: 0,
                required_mib: 256
            }]
        );
        assert_eq!(forecast.shortages[0].code(), "NETWORK_MEMORY");
    }
    #[test]
    fn history_blocks_only_when_cleanup_cannot_make_room() {
        let cleanup = evaluate(
            &measured(300, 0),
            MIB,
            MIB,
            HistoryOutlook::Fits { cleanup_entries: 48 },
        );
        assert!(cleanup.admitted());
        assert_eq!(cleanup.cleanup_entries, 48);
        let full = xkeenwrt_recovery::resources::HistoryFull {
            used_entries: 530,
            limit_entries: 512,
            needed_entries: 145,
            reclaimable_entries: 40,
            used_bytes: 10 * MIB,
            limit_bytes: 64 * MIB,
            needed_bytes: MIB,
            reclaimable_bytes: MIB,
        };
        let blocked = evaluate(&measured(300, 0), MIB, MIB, HistoryOutlook::Full(full));
        assert!(!blocked.admitted());
        assert_eq!(blocked.shortages[0].code(), "NETWORK_HISTORY");
        assert_eq!(
            blocked.shortages[0],
            Shortage::History {
                used_entries: 530,
                limit_entries: 512,
                needed_entries: 145,
                reclaimable_entries: 40,
                used_mib: 10,
                limit_mib: 64,
                needed_mib: 1,
                reclaimable_mib: 1,
            }
        );
    }
    #[test]
    fn limits_reject_each_exhausted_resource_with_its_own_code() {
        let ok = Measured {
            memory_available: 256 * MIB,
            memory_reclaimable: 0,
            tmp_free: 34 * MIB,
            tmp_block: 1,
            flash_free: 34 * MIB,
            flash_block: 1,
        };
        assert!(evaluate(&ok, MIB, 2 * MIB, fits()).admitted());
        let tmp = Measured {
            tmp_free: 34 * MIB - 1,
            ..ok
        };
        assert_eq!(evaluate(&tmp, MIB, 2 * MIB, fits()).shortages[0].code(), "NETWORK_TMP");
        let flash = Measured {
            flash_free: 34 * MIB - 1,
            ..ok
        };
        assert_eq!(
            evaluate(&flash, MIB, 2 * MIB, fits()).shortages[0].code(),
            "NETWORK_FLASH"
        );
        let memory = Measured {
            memory_available: 256 * MIB - 1,
            ..ok
        };
        assert_eq!(
            evaluate(&memory, MIB, 2 * MIB, fits()).shortages[0].code(),
            "NETWORK_MEMORY"
        );
        assert!(!evaluate(&ok, MIB, 2 * MIB, HistoryOutlook::Unknown).admitted());
    }
    #[test]
    fn history_counts_nested_pinned_bytes_and_never_deletes_them() {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let dir = std::env::temp_dir().join(format!("xkeen-history-cap-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let pinned = dir.join("pinned");
        std::fs::create_dir(&pinned).unwrap();
        std::fs::set_permissions(&pinned, std::fs::Permissions::from_mode(0o700)).unwrap();
        // History files are private like production writes; never inherit the caller's umask.
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(pinned.join("config.yaml"))
            .unwrap();
        file.set_len(64 * MIB).unwrap();
        std::fs::rename(&pinned, dir.join("history")).unwrap();
        assert_eq!(xkeenwrt_recovery::resources::history_size(&dir).unwrap(), 64 * MIB);
        assert!(
            xkeenwrt_recovery::resources::plan_history_append(
                &dir,
                &xkeenwrt_recovery::resources::HistoryNeed {
                    bytes: 1,
                    ..Default::default()
                },
                &Default::default()
            )
            .is_err()
        );
        assert_eq!(
            std::fs::metadata(dir.join("history/config.yaml")).unwrap().len(),
            64 * MIB
        );
        let history_file = dir.join("history/config.yaml");
        std::fs::set_permissions(&history_file, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(xkeenwrt_recovery::resources::history_size(&dir).is_err());
        assert!(history_file.exists());
        std::fs::set_permissions(&history_file, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(xkeenwrt_recovery::resources::history_size(&dir).unwrap(), 64 * MIB);
        file.set_len(64 * MIB + 1).unwrap();
        assert!(xkeenwrt_recovery::resources::history_size(&dir).is_err());
        assert!(dir.join("history/config.yaml").exists());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
