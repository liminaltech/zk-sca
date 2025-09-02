#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]
#![deny(warnings)]
#![deny(rust_2018_idioms)]
#![deny(clippy::all, clippy::pedantic, clippy::nursery)]

extern crate alloc;

mod error;
pub use error::ScaError;

mod guest;
pub use guest::{GuestInput, GuestOutput, GuestOutputV0};

mod merkle;
pub use merkle::{MerkleLeaf, MerklePathNode, PartialMerkleArchive};

pub use zk_sca_types::{
    Dependency, LicenseExpr, LicensePolicy, NonEmpty, PackageManager, PackageManagerSpec,
    PermittedDependencies, SourceBundle, Version,
};
