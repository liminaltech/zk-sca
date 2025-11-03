use risc0_zkvm::{ExecutorEnv, default_prover};
use std::sync::{LazyLock, Mutex};
use zk_sca_guest::SCA_ELF;
use zk_sca_guest_abi::{GuestInput, MerkleLeaf, PartialMerkleArchive, ScaError};
use zk_sca_guest_abi_utils::{block_count, parse_tar_header};
use zk_sca_types::{PackageManager, PackageManagerSpec, Version};

mod common;
use crate::common::{load_cargo_archive, load_permitted_deps};

// Protect RISC-0 environment when running tests in parallel.
static PROVE_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

fn prove_should_fail(input: GuestInput, expected: ScaError) {
    let _lock = PROVE_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    unsafe { std::env::set_var("RISC0_DEV_MODE", "1") };

    let exec_env = ExecutorEnv::builder()
        .write(&input)
        .unwrap()
        .build()
        .unwrap();
    let err = match default_prover().prove(exec_env, SCA_ELF) {
        Ok(_) => {
            unsafe { std::env::remove_var("RISC0_DEV_MODE") };
            panic!("Malicious input unexpectedly succeeded");
        }
        Err(e) => {
            unsafe { std::env::remove_var("RISC0_DEV_MODE") };
            e
        }
    };

    let code_val: u32 = err
        .to_string()
        .split_once('|')
        .and_then(|(c, _)| c.strip_prefix("Guest panicked: "))
        .and_then(|s| s.parse().ok())
        .unwrap_or_default();

    assert_eq!(
        code_val, expected as u32,
        "Expected {:?} (code {}), got {} – {}",
        expected, expected as u32, code_val, err
    );
}

fn run_guest_expect_invalid(archive: PartialMerkleArchive) {
    let permitted = load_permitted_deps("permitted-dependencies.json");
    let guest_input = GuestInput {
        src_archive: archive,
        permitted_deps: permitted,
        license_policy: None,
    };
    prove_should_fail(guest_input, ScaError::InvalidMerkleArchive);
}

// Merkle-tree integrity tests
mod merkle_integrity {
    use super::*;

    #[test]
    fn reject_zero_root_hash() {
        let archive = PartialMerkleArchive {
            resolved_with: PackageManagerSpec::new(PackageManager::Cargo, Version::new(0, 0, 0)),
            root_hash: [0u8; 32],
            count_leaf: MerkleLeaf {
                data: [0u8; 512],
                path: Vec::new(),
            },
            header_leaves: Vec::new(),
            dependency_file_leaves: Vec::new(),
            dependency_file_header_indices: Vec::new(),
        };
        run_guest_expect_invalid(archive);
    }

    #[test]
    fn reject_empty_count_leaf_path() {
        let mut archive = load_cargo_archive("safe.tar.gz");
        archive.count_leaf.path.clear();
        run_guest_expect_invalid(archive);
    }

    #[test]
    fn reject_missing_header_proof() {
        let mut archive = load_cargo_archive("safe.tar.gz");
        assert!(archive.header_leaves.len() > 1);
        archive.header_leaves.pop();
        run_guest_expect_invalid(archive);
    }

    #[test]
    fn reject_duplicate_header_name() {
        let mut archive = load_cargo_archive("safe.tar.gz");
        let duplicate = archive.header_leaves[0].clone();
        archive.header_leaves.push(duplicate);
        run_guest_expect_invalid(archive);
    }

    #[test]
    fn reject_corrupt_count_leaf_data() {
        let mut archive = load_cargo_archive("safe.tar.gz");
        archive.count_leaf.data[0] ^= 0x80;
        run_guest_expect_invalid(archive);
    }

    #[test]
    fn reject_header_data_bit_flip() {
        let mut archive = load_cargo_archive("safe.tar.gz");
        if let Some(first) = archive.header_leaves.first_mut() {
            first.data[0] ^= 0x01;
        }
        run_guest_expect_invalid(archive);
    }

    #[test]
    fn reject_dependency_file_bit_flip() {
        let mut archive = load_cargo_archive("safe.tar.gz");
        if let Some(first) = archive.dependency_file_leaves.first_mut() {
            first.data[0] ^= 0x01;
        }
        run_guest_expect_invalid(archive);
    }

    #[test]
    fn reject_dependency_file_invalid_utf8() {
        let mut archive = load_cargo_archive("safe.tar.gz");

        if let Some(block) = archive.dependency_file_leaves.first_mut() {
            block.data[10] = 0xFF;
        }

        run_guest_expect_invalid(archive);
    }

    #[test]
    fn reject_truncated_dependency_file_leaves_list() {
        let mut archive = load_cargo_archive("safe.tar.gz");
        assert!(archive.dependency_file_leaves.pop().is_some());
        run_guest_expect_invalid(archive);
    }

    #[test]
    fn reject_truncated_header_proof_path() {
        let mut archive = load_cargo_archive("safe.tar.gz");
        if let Some(first) = archive.header_leaves.first_mut() {
            first.path.clear();
        }
        run_guest_expect_invalid(archive);
    }
}

// tar integrity tests
mod tar_integrity {
    use super::*;

    #[test]
    fn reject_header_size_underreported() {
        use core::ops::Range;

        // Size field in a USTAR header is octal ASCII at bytes 124–135 inclusive.
        const SIZE_FIELD: Range<usize> = 124..136;

        let mut archive = load_cargo_archive("safe.tar.gz");

        let pos = archive
            .header_leaves
            .iter()
            .position(|leaf| {
                let hdr = parse_tar_header(&leaf.data);
                hdr.name.ends_with("/Cargo.lock") || hdr.name == "Cargo.lock"
            })
            .unwrap();
        archive.header_leaves[pos].data[SIZE_FIELD].copy_from_slice(b"00000000000\0");

        run_guest_expect_invalid(archive);
    }

    #[test]
    fn reject_header_count_too_small() {
        let mut archive = load_cargo_archive("safe.tar.gz");
        archive.count_leaf.data.fill(0);
        archive.count_leaf.data[0] = b'1';
        run_guest_expect_invalid(archive);
    }

    #[test]
    fn reject_header_count_too_large() {
        let mut archive = load_cargo_archive("safe.tar.gz");
        // Claim one more header than actually present.
        let actual = archive.header_leaves.len();
        let claim = actual + 1;
        let s = claim.to_string();
        archive.count_leaf.data.fill(0);
        archive.count_leaf.data[..s.len()].copy_from_slice(s.as_bytes());
        run_guest_expect_invalid(archive);
    }

    #[test]
    fn reject_non_numeric_header_count() {
        let mut archive = load_cargo_archive("safe.tar.gz");
        let marker = b"not-a-number";
        archive.count_leaf.data[..marker.len()].copy_from_slice(marker);
        archive.count_leaf.data[marker.len()..].fill(0);
        run_guest_expect_invalid(archive);
    }

    #[test]
    fn reject_extra_dependency_without_header() {
        let mut archive = load_cargo_archive("safe.tar.gz");
        // Insert a duplicate leaf at the front and remove one from the end so
        // the total count stays the same but every block is shifted by one.
        if let Some(first_leaf) = archive.dependency_file_leaves.first().cloned() {
            archive.dependency_file_leaves.insert(0, first_leaf);
            archive.dependency_file_leaves.pop();
        }
        run_guest_expect_invalid(archive);
    }

    #[test]
    fn reject_excess_dependency_file_leaves() {
        let mut archive = load_cargo_archive("safe.tar.gz");
        if let Some(extra_leaf) = archive.dependency_file_leaves.last().cloned() {
            archive.dependency_file_leaves.push(extra_leaf);
        }
        run_guest_expect_invalid(archive);
    }

    #[test]
    fn reject_scrambled_dependency_file_leaves_order() {
        let mut archive = load_cargo_archive("safe.tar.gz");
        // Swap first and last proof to scramble order.
        let last = archive.dependency_file_leaves.len() - 1;
        archive.dependency_file_leaves.swap(0, last);
        run_guest_expect_invalid(archive);
    }
}

// Cargo integrity tests
mod cargo_integrity {
    use super::*;

    #[test]
    fn reject_missing_cargo_toml_header() {
        let mut archive = load_cargo_archive("safe.tar.gz");
        // Find the first header whose TarHeader.name ends with Cargo.toml.
        let pos = archive
            .header_leaves
            .iter()
            .position(|leaf| {
                let hdr = parse_tar_header(&leaf.data);
                hdr.name == "Cargo.toml" || hdr.name.ends_with("/Cargo.toml")
            })
            .expect("Cargo.toml header not found");
        archive.header_leaves.remove(pos);
        run_guest_expect_invalid(archive);
    }

    #[test]
    fn reject_missing_cargo_lock_header() {
        let mut archive = load_cargo_archive("safe.tar.gz");
        let pos = archive
            .header_leaves
            .iter()
            .position(|leaf| {
                let hdr = parse_tar_header(&leaf.data);
                hdr.name == "Cargo.lock" || hdr.name.ends_with("/Cargo.lock")
            })
            .expect("Cargo.lock header not found");
        archive.header_leaves.remove(pos);
        run_guest_expect_invalid(archive);
    }

    #[test]
    fn reject_missing_cargo_toml_data_blocks() {
        let mut archive = load_cargo_archive("safe.tar.gz");
        // Build the same filtered header list the builder would.
        let mut toml_offset = 0;
        let mut toml_blocks = 0;
        for leaf in &archive.header_leaves {
            let hdr = parse_tar_header(&leaf.data);
            if hdr.name == "Cargo.toml" || hdr.name.ends_with("/Cargo.toml") {
                toml_blocks = block_count(hdr.size);
                break;
            }
            if hdr.name == "Cargo.toml"
                || hdr.name.ends_with("/Cargo.toml")
                || hdr.name == "Cargo.lock"
                || hdr.name.ends_with("/Cargo.lock")
            {
                toml_offset += block_count(hdr.size);
            }
        }
        assert!(toml_blocks > 0, "no Cargo.toml data blocks found");
        // Now drop exactly those from dependency_file_leaves.
        let mut deps = archive.dependency_file_leaves.clone();
        deps.drain(toml_offset..toml_offset + toml_blocks);
        archive.dependency_file_leaves = deps;
        run_guest_expect_invalid(archive);
    }

    #[test]
    fn reject_missing_cargo_lock_data_blocks() {
        let mut archive = load_cargo_archive("safe.tar.gz");
        let mut lock_offset = 0;
        let mut lock_blocks = 0;
        for leaf in &archive.header_leaves {
            let hdr = parse_tar_header(&leaf.data);
            if hdr.name == "Cargo.lock" || hdr.name.ends_with("/Cargo.lock") {
                lock_blocks = block_count(hdr.size);
                break;
            }
            if hdr.name == "Cargo.toml"
                || hdr.name.ends_with("/Cargo.toml")
                || hdr.name == "Cargo.lock"
                || hdr.name.ends_with("/Cargo.lock")
            {
                lock_offset += block_count(hdr.size);
            }
        }
        assert!(lock_blocks > 0, "no Cargo.lock data blocks found");
        let mut deps = archive.dependency_file_leaves.clone();
        deps.drain(lock_offset..lock_offset + lock_blocks);
        archive.dependency_file_leaves = deps;
        run_guest_expect_invalid(archive);
    }

    #[test]
    fn reject_manifest_lock_mismatch() {
        let archive = load_cargo_archive("safe_lockfile_unsafe_manifest.tar.gz");
        let permitted = load_permitted_deps("permitted-dependencies.json");
        let guest_input = GuestInput {
            src_archive: archive,
            permitted_deps: permitted,
            license_policy: None,
        };
        prove_should_fail(guest_input, ScaError::ManifestLockMismatch);
    }

    #[test]
    fn reject_missing_lockfile() {
        let archive = load_cargo_archive("missing_lockfile.tar.gz");
        let permitted = load_permitted_deps("permitted-dependencies.json");
        let guest_input = GuestInput {
            src_archive: archive,
            permitted_deps: permitted,
            license_policy: None,
        };
        prove_should_fail(guest_input, ScaError::MissingLockfile);
    }

    #[test]
    fn reject_missing_workspace() {
        let archive = load_cargo_archive("missing_workspace.tar.gz");
        let permitted = load_permitted_deps("permitted-dependencies.json");
        let guest_input = GuestInput {
            src_archive: archive,
            permitted_deps: permitted,
            license_policy: None,
        };
        prove_should_fail(guest_input, ScaError::InvalidWorkspaceCount);
    }

    #[test]
    fn reject_multi_workspace_single_pkgs() {
        let archive = load_cargo_archive("multi_workspace_single_pkgs.tar.gz");
        let permitted = load_permitted_deps("permitted-dependencies.json");
        let guest_input = GuestInput {
            src_archive: archive,
            permitted_deps: permitted,
            license_policy: None,
        };
        prove_should_fail(guest_input, ScaError::InvalidWorkspaceCount);
    }

    #[test]
    fn reject_multi_workspace_virtual() {
        let archive = load_cargo_archive("multi_workspace_virtual.tar.gz");
        let permitted = load_permitted_deps("permitted-dependencies.json");
        let guest_input = GuestInput {
            src_archive: archive,
            permitted_deps: permitted,
            license_policy: None,
        };
        prove_should_fail(guest_input, ScaError::InvalidWorkspaceCount);
    }

    #[test]
    fn reject_multi_workspace_mixed() {
        let archive = load_cargo_archive("multi_workspace_mixed.tar.gz");
        let permitted = load_permitted_deps("permitted-dependencies.json");
        let guest_input = GuestInput {
            src_archive: archive,
            permitted_deps: permitted,
            license_policy: None,
        };
        prove_should_fail(guest_input, ScaError::InvalidWorkspaceCount);
    }

    #[test]
    fn reject_cargo_lockfile_v1() {
        let archive = load_cargo_archive("cargo_lock_v1.tar.gz");
        let permitted = load_permitted_deps("permitted-dependencies.json");
        let guest_input = GuestInput {
            src_archive: archive,
            permitted_deps: permitted,
            license_policy: None,
        };
        prove_should_fail(guest_input, ScaError::UnsupportedLockfileVersion);
    }

    #[test]
    fn reject_cargo_lockfile_v2() {
        let archive = load_cargo_archive("cargo_lock_v2.tar.gz");
        let permitted = load_permitted_deps("permitted-dependencies.json");
        let guest_input = GuestInput {
            src_archive: archive,
            permitted_deps: permitted,
            license_policy: None,
        };
        prove_should_fail(guest_input, ScaError::UnsupportedLockfileVersion);
    }
}

// Policy tests
mod policy_enforcement {
    use super::*;

    #[test]
    fn reject_disallowed_dependency() {
        let archive = load_cargo_archive("safe.tar.gz");
        let permitted = load_permitted_deps("permitted-dependencies-minimal.json");
        let guest_input = GuestInput {
            src_archive: archive,
            permitted_deps: permitted,
            license_policy: None,
        };
        prove_should_fail(guest_input, ScaError::DisallowedDependency);
    }

    #[test]
    fn reject_disallowed_version() {
        let archive = load_cargo_archive("vuln.tar.gz");
        let permitted = load_permitted_deps("permitted-dependencies.json");
        let guest_input = GuestInput {
            src_archive: archive,
            permitted_deps: permitted,
            license_policy: None,
        };
        prove_should_fail(guest_input, ScaError::DisallowedVersion);
    }

    #[test]
    fn reject_disallowed_version_virtual_workspace() {
        let archive = load_cargo_archive("virtual_workspace_vuln.tar.gz");
        let permitted = load_permitted_deps("permitted-dependencies.json");
        let guest_input = GuestInput {
            src_archive: archive,
            permitted_deps: permitted,
            license_policy: None,
        };
        prove_should_fail(guest_input, ScaError::DisallowedVersion);
    }

    #[test]
    fn reject_disallowed_version_non_virtual_workspace() {
        let archive = load_cargo_archive("non_virtual_workspace_vuln.tar.gz");
        let permitted = load_permitted_deps("permitted-dependencies.json");
        let guest_input = GuestInput {
            src_archive: archive,
            permitted_deps: permitted,
            license_policy: None,
        };
        prove_should_fail(guest_input, ScaError::DisallowedVersion);
    }

    #[test]
    fn reject_disallowed_license() {
        let archive = load_cargo_archive("safe.tar.gz");
        let permitted = load_permitted_deps("permitted-dependencies.json");
        let raw = vec!["BSL-1.0".to_owned()];
        let json = serde_json::to_string(&raw).unwrap();
        let license_policy = serde_json::from_str(&json).ok();

        let guest_input = GuestInput {
            src_archive: archive,
            permitted_deps: permitted,
            license_policy,
        };
        prove_should_fail(guest_input, ScaError::DisallowedLicense);
    }

    #[test]
    fn reject_undeclared_dep() {
        let archive = load_cargo_archive("undeclared_dep.tar.gz");
        let permitted = load_permitted_deps("permitted-dependencies.json");
        let guest_input = GuestInput {
            src_archive: archive,
            permitted_deps: permitted,
            license_policy: None,
        };
        prove_should_fail(guest_input, ScaError::UndeclaredLockfileDependency);
    }
}
