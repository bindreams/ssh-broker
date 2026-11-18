//! Helpers shared by the unit tests on every host: the elevation policies a login can ask for. The
//! Windows-only helpers are in the `windows` submodule, re-exported here.

use crate::protocol::ElevationPolicy;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::*;

pub const POLICIES: [ElevationPolicy; 4] = [
    ElevationPolicy::Never,
    ElevationPolicy::Prompt,
    ElevationPolicy::AutoApprove,
    ElevationPolicy::Always,
];

/// Every answer a login can give: each of the four policies, and none.
pub fn asked_policies() -> impl Iterator<Item = Option<ElevationPolicy>> {
    POLICIES.map(Some).into_iter().chain([None])
}
