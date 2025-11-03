#![deny(unsafe_code)]
#![deny(warnings)]
#![deny(rust_2018_idioms)]
#![deny(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::new_without_default, clippy::missing_errors_doc)]

use risc0_zkvm::sha::Digest;
use zk_sca_guest::SCA_ID;

mod errors;
pub use crate::errors::ProverError;

mod prover;
pub use crate::prover::{Prover, ProverOpts};

mod env_guard;
pub(crate) use crate::env_guard::EnvVarGuard;

/// Returns the program image ID as a `Digest`.
#[must_use]
#[inline]
pub fn program_id_digest() -> Digest {
    Digest::from(SCA_ID)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn program_id_is_32_bytes() {
        let d = program_id_digest();
        assert_eq!(d.as_bytes().len(), 32);
    }
}
