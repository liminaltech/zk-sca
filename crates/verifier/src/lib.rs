#![forbid(unsafe_code)]
#![deny(warnings)]
#![deny(rust_2018_idioms)]
#![deny(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::missing_errors_doc)]

use risc0_zkvm::{Journal, Receipt, sha::Digest};
use zk_sca_guest_abi::GuestOutput;
use zk_sca_types::{LicensePolicy, PermittedDependencies};

#[derive(Debug)]
pub enum VerifierError {
    ReceiptVerificationFailed(String),
    JournalDecodeError(String),
    UnsupportedJournalVersion(u32),
}

impl std::fmt::Display for VerifierError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ReceiptVerificationFailed(msg) => {
                write!(f, "Receipt verification failed: {msg}")
            }
            Self::JournalDecodeError(msg) => {
                write!(f, "Journal decoding failed: {msg}")
            }
            Self::UnsupportedJournalVersion(v) => {
                write!(
                    f,
                    "Unsupported journal version {v}. Please upgrade verifier."
                )
            }
        }
    }
}

impl std::error::Error for VerifierError {}

/// Verify the proof’s `Receipt` against the program image ID.
///
/// Returns `Ok(())` on success or a `VerifierError` with the failure reason.
pub fn verify_receipt(receipt: &Receipt, image_id: Digest) -> Result<(), VerifierError> {
    receipt
        .verify(image_id)
        .map_err(|e| VerifierError::ReceiptVerificationFailed(format!("{e:?}")))
}

#[derive(Debug)]
pub struct DecodedJournal {
    pub root_hash: [u8; 32],
    pub permitted_deps: PermittedDependencies,
    pub license_policy: Option<LicensePolicy>,
}

/// Decode and version-check the journal emitted by the guest.
///
/// Returns a `DecodedJournal` on success or a `VerifierError` if the journal is
/// malformed or uses an unsupported version.
pub fn decode_journal(journal: &Journal) -> Result<DecodedJournal, VerifierError> {
    let guest_out: GuestOutput = journal
        .decode()
        .map_err(|e| VerifierError::JournalDecodeError(format!("{e:?}")))?;

    match guest_out {
        GuestOutput::V0(v0) => Ok(DecodedJournal {
            root_hash: v0.root_hash,
            permitted_deps: v0.permitted_deps,
            license_policy: v0.license_policy,
        }),
        other => Err(VerifierError::UnsupportedJournalVersion(other.version())),
    }
}
