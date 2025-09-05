use crate::{PackageManager, TypesError, license::LicenseExpr, validate_nonempty_unique};
use alloc::{format, string::String, vec::Vec};
use nonempty::NonEmpty;
use semver::Version;

use serde::{
    Deserialize, Serialize,
    de::{Deserializer, Error as DeError},
};

#[non_exhaustive]
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Dependency {
    name: String,
    license: LicenseExpr,
    min_safe_version: Version,
}

impl Dependency {
    #[must_use]
    pub const fn new(name: String, license: LicenseExpr, min_safe_version: Version) -> Self {
        Self {
            name,
            license,
            min_safe_version,
        }
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// SPDX licence expression under which the package is distributed.
    #[must_use]
    pub const fn license(&self) -> &LicenseExpr {
        &self.license
    }

    /// Lowest package version considered free of known CVEs.
    #[must_use]
    pub const fn min_safe_version(&self) -> &Version {
        &self.min_safe_version
    }
}

#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct PermittedDependencies {
    resolvable_with: PackageManager,
    dependencies: NonEmpty<Dependency>,
}

impl PermittedDependencies {
    /// `dependencies` must contain at least one entry, and every entry must be unique.
    pub fn try_new(
        resolvable_with: PackageManager,
        dependencies: Vec<Dependency>,
    ) -> Result<Self, TypesError> {
        let non_empty = validate_nonempty_unique(
            dependencies,
            |dep: &Dependency| dep.name.clone(),
            |dup: &Dependency| format!("duplicate dependency `{}`", dup.name),
        )
        .map_err(TypesError::Validation)?;
        Ok(Self {
            resolvable_with,
            dependencies: non_empty,
        })
    }

    #[must_use]
    pub const fn resolvable_with(&self) -> PackageManager {
        self.resolvable_with
    }

    #[must_use]
    pub const fn dependencies(&self) -> &NonEmpty<Dependency> {
        &self.dependencies
    }
}

impl<'de> Deserialize<'de> for PermittedDependencies {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Define a temporary struct to mirror the JSON shape.
        #[derive(Deserialize)]
        struct Raw {
            resolvable_with: PackageManager,
            dependencies: Vec<Dependency>,
        }

        let Raw {
            resolvable_with,
            dependencies,
        } = Raw::deserialize(deserializer)?;

        Self::try_new(resolvable_with, dependencies).map_err(DeError::custom)
    }
}
