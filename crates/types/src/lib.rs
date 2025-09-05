#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]
#![deny(warnings)]
#![deny(rust_2018_idioms)]
#![deny(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::module_name_repetitions, clippy::missing_errors_doc)]

extern crate alloc;

mod bundle;
pub use bundle::SourceBundle;

mod dependency;
pub use dependency::{Dependency, PermittedDependencies};

mod error;
pub use error::TypesError;

mod license;
pub use license::{LicenseExpr, LicensePolicy};

mod package_manager;
pub use package_manager::{PackageManager, PackageManagerSpec};

mod validation;
pub(crate) use validation::validate_nonempty_unique;

pub use nonempty::NonEmpty;
pub use semver::Version;
