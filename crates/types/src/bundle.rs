use crate::PackageManagerSpec;
use alloc::{sync::Arc, vec::Vec};

#[non_exhaustive]
#[derive(Clone, Debug, PartialEq)]
pub struct SourceBundle {
    tar_gz: Arc<[u8]>,
    resolved_with: PackageManagerSpec,
}

impl SourceBundle {
    #[must_use]
    pub const fn new(tar_gz: Arc<[u8]>, resolved_with: PackageManagerSpec) -> Self {
        Self {
            tar_gz,
            resolved_with,
        }
    }

    #[must_use]
    pub fn from_vec(tar_gz: Vec<u8>, resolved_with: PackageManagerSpec) -> Self {
        Self::new(tar_gz.into(), resolved_with)
    }

    /// A gzipped tarball containing the full source tree to be analyzed.
    #[must_use]
    pub fn tar_gz(&self) -> &[u8] {
        &self.tar_gz
    }

    /// The package manager version that resolved dependencies and built the binary.
    #[must_use]
    pub const fn resolved_with(&self) -> &PackageManagerSpec {
        &self.resolved_with
    }
}
