use hex::FromHex;
use risc0_zkvm::{Receipt, sha::Digest};
use std::{
    fs,
    path::{Path, PathBuf},
};
use zk_sca_verifier::verify_receipt;

fn fixture_path(name: &str) -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest_dir)
        .join("..")
        .join("..")
        .join("fixtures")
        .join(name)
}

fn parse_program_id(hex_str: &str) -> Digest {
    let bytes = Vec::from_hex(hex_str).unwrap_or_else(|e| panic!("invalid program ID hex: {e}"));
    assert!(
        bytes.len() == 32,
        "invalid program ID: expected 32 bytes (64 hex chars), got {} bytes",
        bytes.len()
    );
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Digest::from(arr)
}

#[test]
fn verify_receipt_happy_path() -> Result<(), Box<dyn std::error::Error>> {
    let path = fixture_path("valid-receipt.bin");
    let bytes = fs::read(&path).map_err(|e| format!("read {}: {e}", path.display()))?;

    let receipt: Receipt = bincode::deserialize(&bytes)
        .map_err(|e| format!("deserialize Receipt from {}: {e}", path.display()))?;

    let image_id =
        parse_program_id("41d8e8bc920aec3d54c9e0179ab3ea7ba374428e3f2987a691f75f9019a51613");

    verify_receipt(&receipt, image_id).map_err(|e| format!("verify_receipt failed: {e}"))?;

    Ok(())
}
