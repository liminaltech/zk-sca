use std::sync::{LazyLock, Mutex};
use zk_sca_prover::{Prover, ProverError};

mod common;
use crate::common::{load_cargo_bundle, load_permitted_deps};

/// Global mutex to serialize env-var edits across tests.
static ENV_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

fn build_prover(cycle_report: bool, dev_mode: bool) -> Prover {
    let bundle = load_cargo_bundle("safe.tar.gz");
    let permitted = load_permitted_deps("permitted-dependencies-minimal.json");

    let mut prover = Prover::new()
        .with_bundle(bundle)
        .with_permitted_deps(&permitted);

    if dev_mode {
        prover = prover.with_dev_mode(true);
    }
    if cycle_report {
        prover = prover.with_cycle_report(true);
    }
    prover
}

fn assert_env_conflict(key: &'static str, preset_val: &str, cycle_report: bool, dev_mode: bool) {
    let _lock = ENV_LOCK.lock().unwrap();

    let old = std::env::var(key).ok();
    for var in ["RISC0_DEV_MODE", "RISC0_INFO", "RUST_LOG"] {
        unsafe { std::env::remove_var(var) };
    }
    unsafe { std::env::set_var(key, preset_val) };

    let err = build_prover(cycle_report, dev_mode).prove().unwrap_err();
    match err {
        ProverError::EnvVarConflict(k, v) => {
            assert_eq!(&*k, key, "Conflict key mismatch – wanted {key}, got {k}");
            assert_eq!(
                &*v, preset_val,
                "Conflict val mismatch – wanted {preset_val}, got {v}"
            );
        }
        other => panic!("Expected EnvVarConflict for {key}, got {:?}", other),
    }

    // Restore prior value or remove if none.
    match old {
        Some(v) => unsafe { std::env::set_var(key, v) },
        None => unsafe { std::env::remove_var(key) },
    }
}

#[test]
fn conflict_risc0_dev_mode_when_disabled() {
    assert_env_conflict("RISC0_DEV_MODE", "1", false, false);
}

#[test]
fn conflict_risc0_info_when_cycle_report_disabled() {
    assert_env_conflict("RISC0_INFO", "1", false, false);
}

#[test]
fn conflict_rust_log_when_cycle_report_disabled() {
    assert_env_conflict("RUST_LOG", "trace", false, false);
}
