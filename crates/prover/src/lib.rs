#![deny(unsafe_code)]
#![deny(warnings)]
#![deny(rust_2018_idioms)]
#![deny(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::new_without_default, clippy::missing_errors_doc)]

mod errors;
pub use crate::errors::ProverError;

mod prover;
pub use crate::prover::{Prover, ProverOpts};

mod env_guard;
pub(crate) use crate::env_guard::EnvVarGuard;
