use std::{
    env,
    path::{Path, PathBuf},
    process::Command,
};

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures")
}

fn run_prove(archive: &Path, metadata: &Path, receipt: &Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_zk-sca-cli"))
        .arg("prove")
        .arg("-a")
        .arg(archive)
        .arg("--package-manager")
        .arg("Cargo")
        .arg("--package-manager-version")
        .arg("1.81.0")
        .arg("-p")
        .arg(metadata)
        .arg("--output")
        .arg(receipt)
        .arg("--dev-mode")
        .output()
        .expect("spawn zk-sca-cli")
}

#[test]
fn safe_archive_succeeds() {
    let fx = fixtures();
    let archive = fx.join("safe.tar.gz");
    let metadata = fx.join("permitted-dependencies.json");
    let receipt = fx.join("safe-receipt.bin");

    let out = run_prove(&archive, &metadata, &receipt);
    assert!(
        out.status.success(),
        "expected success but got {}\nstdout: {}\nstderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn vuln_archive_fails() {
    let fx = fixtures();
    let archive = fx.join("vuln.tar.gz");
    let metadata = fx.join("permitted-dependencies.json");
    let receipt = fx.join("vuln-receipt.bin");

    let out = run_prove(&archive, &metadata, &receipt);
    assert!(
        !out.status.success(),
        "expected failure but CLI returned success!\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn safe_archive_only_allow_apache2_fails() {
    let fx = fixtures();
    let archive = fx.join("safe.tar.gz");
    let metadata = fx.join("permitted-dependencies.json");
    let receipt = fx.join("safe-apache-only-receipt.bin");

    let out = Command::new(env!("CARGO_BIN_EXE_zk-sca-cli"))
        .arg("prove")
        .arg("-a")
        .arg(&archive)
        .arg("-p")
        .arg(&metadata)
        .arg("--output")
        .arg(&receipt)
        .arg("--allowed-licenses")
        .arg("Apache-2.0")
        .arg("--dev-mode")
        .output()
        .expect("spawn zk-sca-cli");

    assert!(
        !out.status.success(),
        "expected failure when only allowing Apache-2.0 (no MIT) but CLI returned success!\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}
