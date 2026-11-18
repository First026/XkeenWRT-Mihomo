//! Fixed accepted-selection adapter; independent rescue reads the same schema.
use crate::configuration::ActivationError;
pub(crate) use xkeenwrt_recovery::input_state::Selection;
pub(crate) fn load() -> Result<Selection, ActivationError> {
    xkeenwrt_recovery::input_state::load().map_err(|_| ActivationError::Storage)
}
pub(crate) fn save(s: &Selection) -> Result<(), ActivationError> {
    xkeenwrt_recovery::input_state::save(s).map_err(|_| ActivationError::Storage)
}

pub(crate) fn settle() -> Result<(), ActivationError> {
    if let Some(j) = super::networking::driver::OpenWrtDriver::<super::validator::ProcessValidator>::secure_journal()
        .map_err(|_| ActivationError::Storage)?
    {
        settle_for(&j)?;
    }
    Ok(())
}
pub(crate) fn settle_for(j: &xkeenwrt_recovery::Journal) -> Result<(), ActivationError> {
    xkeenwrt_recovery::input_state::settle_selection(j).map_err(|_| ActivationError::Storage)
}
