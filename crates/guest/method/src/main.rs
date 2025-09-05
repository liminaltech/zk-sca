#![no_main]
#![no_std]
#![forbid(unsafe_code)]
#![deny(warnings)]
#![deny(rust_2018_idioms)]
#![deny(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::no_mangle_with_rust_abi)]

extern crate alloc;

use alloc::{format, string::String};
use risc0_zkvm::guest::env;
use zk_sca_guest_abi::{GuestInput, GuestOutput, GuestOutputV0, PackageManager, ScaError, Version};
use zk_sca_guest_abi_utils::validate_merkle_archive;

mod audit;
use audit::audit_dependencies;
mod cargo;
use cargo::validate_cargo_archive;

risc0_zkvm::guest::entry!(main);

fn main() {
    if let Err((code, detail)) = real_main() {
        panic!("{}|{}", code as u32, detail);
    }
}

fn real_main() -> Result<(), (ScaError, String)> {
    let guest_input: GuestInput = env::read();
    let merkle_archive = guest_input.src_archive;
    let permitted = guest_input.permitted_deps;
    let license_policy = guest_input.license_policy;
    if !(merkle_archive.resolved_with.manager() == permitted.resolvable_with()) {
        return Err((
            ScaError::InconsistentPackageManager,
            format!(
                "archive resolved with `{:?}` but permitted deps are resolvable with `{:?}`",
                merkle_archive.resolved_with,
                permitted.resolvable_with()
            ),
        ));
    }

    let vpa = validate_merkle_archive(&merkle_archive)?;

    let spec = merkle_archive.resolved_with;
    let resolved = match (spec.manager(), spec.version()) {
        // Cargo 1.51 is the first stable version that can produce V3 lockfiles.
        (PackageManager::Cargo, version) if version >= &Version::new(1, 51, 0) => {
            validate_cargo_archive(&vpa)?
        }
        _ => {
            return Err((
                ScaError::UnsupportedPackageManager,
                format!("`{spec:?}` is not supported"),
            ));
        }
    };

    audit_dependencies(&resolved, permitted.dependencies(), license_policy.as_ref())?;

    let out_v0 = GuestOutputV0 {
        root_hash: merkle_archive.root_hash,
        permitted_deps: permitted,
        license_policy,
    };
    let out: GuestOutput = out_v0.into();
    env::commit(&out);

    Ok(())
}
