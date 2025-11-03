use crate::{EnvVarGuard, ProverError};
use risc0_zkvm::{ExecutorEnv, Receipt, default_prover};
use std::sync::{LazyLock, Mutex};
use zk_sca_guest::SCA_ELF;
use zk_sca_guest_abi::{self as abi};
use zk_sca_guest_abi_utils::build_merkle_archive;
use zk_sca_types::{LicensePolicy, PermittedDependencies, SourceBundle};

#[non_exhaustive]
#[derive(Debug, Clone, Copy, Default)]
pub struct ProverOpts {
    /// Skip proof generation.
    pub dev_mode: bool,
    /// Log cycle counts.
    pub cycle_report: bool,
}

/// Builder for proof configuration.
///
/// `with_*` setters are pure: each call returns a new `Prover`, so they can be
/// chained in any order. Later calls overwrite earlier ones.
#[derive(Debug, Clone)]
pub struct Prover {
    src_bundle: Option<SourceBundle>,
    permitted_deps: Option<PermittedDependencies>,
    license_policy: Option<LicensePolicy>,
    opts: ProverOpts,
}

impl Prover {
    /// Create an empty `Prover`.
    ///
    /// Call `with_bundle` and `with_permitted_deps` before `prove`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            src_bundle: None,
            permitted_deps: None,
            license_policy: None,
            opts: ProverOpts::default(),
        }
    }

    /// Set the `SourceBundle` to be analyzed. This is required before calling `prove`.
    #[must_use]
    pub fn with_bundle(&self, bundle: SourceBundle) -> Self {
        let mut next = self.clone();
        next.src_bundle = Some(bundle);
        next
    }

    /// Set the `PermittedDependencies` allowlist. This is required before calling `prove`.
    #[must_use]
    pub fn with_permitted_deps(&self, deps: &PermittedDependencies) -> Self {
        let mut next = self.clone();
        next.permitted_deps = Some(deps.clone());
        next
    }

    /// Set the `LicensePolicy`. If unset, all licenses are permitted by default.
    #[must_use]
    pub fn with_license_policy(&self, policy: &LicensePolicy) -> Self {
        let mut next = self.clone();
        next.license_policy = Some(policy.clone());
        next
    }

    /// Enable or disable dev mode (skips proof generation).
    #[must_use]
    pub fn with_dev_mode(&self, enabled: bool) -> Self {
        let mut next = self.clone();
        next.opts.dev_mode = enabled;
        next
    }

    /// Enable or disable cycle-count reporting in the RISC Zero zkVM.
    #[must_use]
    pub fn with_cycle_report(&self, enabled: bool) -> Self {
        let mut next = self.clone();
        next.opts.cycle_report = enabled;
        next
    }

    /// Validate required fields and return a `ProverConfig`, or a `ProverError`.
    pub fn build(&mut self) -> Result<ProverConfig, ProverError> {
        let bundle = self
            .src_bundle
            .take()
            .ok_or(ProverError::MissingSourceArchive)?;

        let permitted_deps = self
            .permitted_deps
            .take()
            .ok_or(ProverError::MissingPermittedDependencies)?;

        Ok(ProverConfig {
            bundle,
            permitted_deps,
            license_policy: self.license_policy.clone(),
            opts: self.opts,
        })
    }

    /// Validate the configuration and run the proof.
    ///
    /// Returns a `risc0_zkvm::Receipt` on success, or a `ProverError` on failure.
    pub fn prove(mut self) -> Result<Receipt, ProverError> {
        let config = self.build()?;
        config.prove()
    }
}

/// Validated configuration used by `prove`.
#[derive(Debug, Clone)]
pub struct ProverConfig {
    pub bundle: SourceBundle,
    pub permitted_deps: PermittedDependencies,
    pub license_policy: Option<LicensePolicy>,
    pub opts: ProverOpts,
}

/// Global lock to prevent concurrent env-var races in `EnvVarGuard`.
static PROVE_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

impl ProverConfig {
    /// Generate the proof using this configuration.
    pub fn prove(self) -> Result<Receipt, ProverError> {
        // Only one proof may flip the RISC0_* env vars at a time.
        let _guard = PROVE_LOCK.lock().expect("prover lock poisoned");
        let _dev_mode_guard = EnvVarGuard::new("RISC0_DEV_MODE", "1", self.opts.dev_mode)?;
        let _risc0_info_guard = EnvVarGuard::new("RISC0_INFO", "1", self.opts.cycle_report)?;
        let _rust_log_guard = EnvVarGuard::new("RUST_LOG", "info", self.opts.cycle_report)?;

        // Construct the Merkle archive from the provided source tar.gz.
        let merkle_archive = build_merkle_archive(&self.bundle)
            .map_err(|e| ProverError::ArchiveParseError(e.to_string()))?;

        // Create the ABI‐level GuestInput that will be written into the prover environment.
        let guest_input = abi::GuestInput {
            src_archive: merkle_archive,
            permitted_deps: self.permitted_deps,
            license_policy: self.license_policy,
        };

        // Build the RISC0 executor environment by writing the GuestInput.
        let exec_env = ExecutorEnv::builder()
            .write(&guest_input)
            .unwrap()
            .build()
            .unwrap();

        // Run the prover. If the guest panics, parse the panic message as "{code}|{detail}".
        let receipt = match default_prover().prove(exec_env, SCA_ELF) {
            Ok(result) => result.receipt,
            Err(e) => {
                let mut panic_msg = e.to_string();
                if let Some(stripped) = panic_msg.strip_prefix("Guest panicked: ") {
                    panic_msg = stripped.to_string();
                }
                if let Some((code_str, detail)) = panic_msg.split_once('|') {
                    if let Ok(code) = code_str.parse::<u32>() {
                        let err = match code {
                            1 => ProverError::DisallowedDependency(detail.to_string()),
                            2 => ProverError::DisallowedVersion(detail.to_string()),
                            3 => ProverError::DisallowedLicense(detail.to_string()),
                            4 => ProverError::UnsupportedLockfileVersion(detail.to_string()),
                            5 => ProverError::InvalidMerkleArchive(detail.to_string()),
                            6 => ProverError::UndeclaredLockfileDependency(detail.to_string()),
                            7 => ProverError::MissingLockfile(detail.to_string()),
                            8 => ProverError::ManifestLockMismatch(detail.to_string()),
                            9 => ProverError::InvalidManifestEncoding(detail.to_string()),
                            10 => ProverError::ManifestParseError(detail.to_string()),
                            11 => ProverError::InvalidLockfileEncoding(detail.to_string()),
                            12 => ProverError::LockfileParseError(detail.to_string()),
                            13 => ProverError::RedundantLockfile(detail.to_string()),
                            14 => ProverError::InvalidWorkspaceCount(detail.to_string()),
                            15 => ProverError::UnsupportedPackageManager(detail.to_string()),
                            16 => ProverError::InconsistentPackageManager(detail.to_string()),
                            _ => ProverError::UnknownGuestError(code, detail.to_string()),
                        };
                        return Err(err);
                    }
                }
                // If we could not parse a valid “code|detail”, treat it as an unknown guest error.
                Err(ProverError::UnknownGuestError(0, panic_msg))?
            }
        };

        Ok(receipt)
    }
}
