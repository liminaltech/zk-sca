use crate::{LicensePolicy, PartialMerkleArchive, PermittedDependencies};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub struct GuestInput {
    /// `MerkleArchive` of only the manifest, header, and dependency blocks needed for SCA.
    pub src_archive: PartialMerkleArchive,
    /// Permitted dependency metadata (name, license, min safe version), grouped by framework.
    pub permitted_deps: PermittedDependencies,
    /// Applied to each dependency. If `None`, skip all license checks.
    pub license_policy: Option<LicensePolicy>,
}

pub const GUEST_OUTPUT_V0: u32 = 0;

#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub struct GuestOutputV0 {
    /// The Merkle root hash of the archive of source code under analysis.
    pub root_hash: [u8; 32],
    /// Per-framework list of dependencies with name, license, and minimum safe version.
    pub permitted_deps: PermittedDependencies,
    /// The license policy applied to the analyzed source code.
    pub license_policy: Option<LicensePolicy>,
}

#[derive(Debug, Deserialize, PartialEq, Serialize)]
#[non_exhaustive]
pub enum GuestOutput {
    #[serde(rename = "0")]
    V0(GuestOutputV0),
}

impl From<GuestOutputV0> for GuestOutput {
    fn from(v0: GuestOutputV0) -> Self {
        Self::V0(v0)
    }
}

impl GuestOutput {
    #[must_use]
    pub const fn version(&self) -> u32 {
        match self {
            Self::V0(_) => GUEST_OUTPUT_V0,
        }
    }

    #[must_use]
    pub const fn as_v0(&self) -> Option<&GuestOutputV0> {
        match self {
            Self::V0(inner) => Some(inner),
        }
    }
}
