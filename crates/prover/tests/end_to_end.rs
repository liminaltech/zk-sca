use zk_sca_prover::{Prover, ProverError};
use zk_sca_types::{LicensePolicy, PackageManager, PackageManagerSpec, SourceBundle, Version};

mod common;
use crate::common::{load_cargo_bundle, load_permitted_deps};

#[test]
fn happy_path_no_dependencies_declared() {
    let bundle = load_cargo_bundle("no_deps.tar.gz");
    let permitted = load_permitted_deps("permitted-dependencies.json");

    let prover = Prover::new()
        .with_bundle(bundle)
        .with_permitted_deps(&permitted)
        .with_dev_mode(true)
        .with_cycle_report(false);

    let result = prover.prove();
    assert!(result.is_ok(), "Expected Ok(Receipt), got {:?}", result);
}

#[test]
fn happy_path_with_dependencies_no_license_policy_no_cycle_report() {
    let bundle = load_cargo_bundle("safe.tar.gz");
    let permitted = load_permitted_deps("permitted-dependencies.json");

    let prover = Prover::new()
        .with_bundle(bundle)
        .with_permitted_deps(&permitted)
        .with_dev_mode(true)
        .with_cycle_report(false);

    let result = prover.prove();
    assert!(result.is_ok(), "Expected Ok(Receipt), got {:?}", result);
}

#[test]
fn happy_path_with_dependencies_virtual_workspace() {
    let bundle = load_cargo_bundle("virtual_workspace_safe.tar.gz");
    let permitted = load_permitted_deps("permitted-dependencies.json");

    let prover = Prover::new()
        .with_bundle(bundle)
        .with_permitted_deps(&permitted)
        .with_dev_mode(true)
        .with_cycle_report(false);

    let result = prover.prove();
    assert!(result.is_ok(), "Expected Ok(Receipt), got {:?}", result);
}

#[test]
fn happy_path_with_dependencies_non_virtual_workspace() {
    let bundle = load_cargo_bundle("non_virtual_workspace_safe.tar.gz");
    let permitted = load_permitted_deps("permitted-dependencies.json");

    let prover = Prover::new()
        .with_bundle(bundle)
        .with_permitted_deps(&permitted)
        .with_dev_mode(true)
        .with_cycle_report(false);

    let result = prover.prove();
    assert!(result.is_ok(), "Expected Ok(Receipt), got {:?}", result);
}

#[test]
fn happy_path_with_dependencies_no_license_policy_with_cycle_report() {
    let bundle = load_cargo_bundle("safe.tar.gz");
    let permitted = load_permitted_deps("permitted-dependencies.json");

    let prover = Prover::new()
        .with_bundle(bundle)
        .with_permitted_deps(&permitted)
        .with_dev_mode(true)
        .with_cycle_report(true);

    let result = prover.prove();
    assert!(result.is_ok(), "Expected Ok(Receipt), got {:?}", result);
}

#[test]
fn happy_path_with_dependencies_and_license_policy_no_cycle_report() {
    let bundle = load_cargo_bundle("safe.tar.gz");
    let permitted = load_permitted_deps("permitted-dependencies.json");

    let raw = vec!["MIT".to_owned()];
    let json = serde_json::to_string(&raw).unwrap();
    let license_policy: LicensePolicy = serde_json::from_str(&json).unwrap();

    let prover = Prover::new()
        .with_bundle(bundle)
        .with_permitted_deps(&permitted)
        .with_license_policy(&license_policy)
        .with_dev_mode(true)
        .with_cycle_report(false);

    let result = prover.prove();
    assert!(result.is_ok(), "Expected Ok(Receipt), got {:?}", result);
}

#[test]
fn happy_path_with_dependencies_and_license_policy_with_cycle_report() {
    let bundle = load_cargo_bundle("safe.tar.gz");
    let permitted = load_permitted_deps("permitted-dependencies.json");

    let raw = vec!["MIT".to_owned()];
    let json = serde_json::to_string(&raw).unwrap();
    let license_policy: LicensePolicy = serde_json::from_str(&json).unwrap();

    let prover = Prover::new()
        .with_bundle(bundle)
        .with_permitted_deps(&permitted)
        .with_license_policy(&license_policy)
        .with_dev_mode(true)
        .with_cycle_report(true);

    let result = prover.prove();
    assert!(result.is_ok(), "Expected Ok(Receipt), got {:?}", result);
}

#[test]
fn missing_source_archive() {
    let permitted = load_permitted_deps("permitted-dependencies.json");
    let result = Prover::new()
        .with_permitted_deps(&permitted)
        .with_dev_mode(true)
        .build();
    assert!(
        matches!(result, Err(ProverError::MissingSourceArchive)),
        "Expected Err(ProverError::MissingSourceArchive), got {:?}",
        result
    );
}

#[test]
fn missing_permitted_dependencies() {
    let bundle = load_cargo_bundle("safe.tar.gz");
    let result = Prover::new()
        .with_bundle(bundle)
        .with_dev_mode(true)
        .build();
    assert!(
        matches!(result, Err(ProverError::MissingPermittedDependencies)),
        "Expected Err(ProverError::MissingPermittedDependencies), got {:?}",
        result
    );
}

#[test]
fn archive_parse_error() {
    let garbage = vec![0u8, 1, 2, 3, 4, 5];
    let bundle = SourceBundle::from_vec(
        garbage,
        PackageManagerSpec::new(PackageManager::Cargo, Version::new(1, 82, 0)),
    );
    let permitted = load_permitted_deps("permitted-dependencies.json");

    let prover = Prover::new()
        .with_bundle(bundle)
        .with_permitted_deps(&permitted)
        .with_dev_mode(true)
        .with_cycle_report(false);

    let result = prover.prove();
    assert!(
        matches!(result, Err(ProverError::ArchiveParseError(_))),
        "Expected Err(ProverError::ArchiveParseError(_)), got {:?}",
        result
    );
}

#[test]
fn reject_pax_tar_format() {
    let bundle = load_cargo_bundle("pax.tar.gz");
    let permitted = load_permitted_deps("permitted-dependencies.json");

    let prover = Prover::new()
        .with_bundle(bundle)
        .with_permitted_deps(&permitted)
        .with_dev_mode(true)
        .with_cycle_report(false);

    let err = prover.prove().unwrap_err();
    assert!(
        matches!(err, ProverError::ArchiveParseError(_)),
        "Expected ArchiveParseError for PAX TAR, got {:?}",
        err
    );
}
