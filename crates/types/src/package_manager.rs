use crate::Version;
use serde::{Deserialize, Serialize};

#[non_exhaustive]
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum PackageManager {
    /// Rust’s Cargo package manager.
    Cargo,
}

#[non_exhaustive]
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct PackageManagerSpec {
    manager: PackageManager,
    version: Version,
}

impl PackageManagerSpec {
    #[must_use]
    pub const fn new(manager: PackageManager, version: Version) -> Self {
        Self { manager, version }
    }

    #[must_use]
    pub const fn manager(&self) -> PackageManager {
        self.manager
    }

    #[must_use]
    pub const fn version(&self) -> &Version {
        &self.version
    }
}
