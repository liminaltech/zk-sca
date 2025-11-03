#![forbid(unsafe_code)]
#![deny(warnings)]
#![deny(rust_2018_idioms)]
#![deny(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::too_many_arguments)]

use clap::{Parser, Subcommand};
use hex::FromHex;
use risc0_zkvm::{Receipt, sha::Digest};
use std::{
    env, fs,
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
};
use zk_sca_prover::{Prover, ProverError, program_id_digest};
use zk_sca_types::{
    LicensePolicy, PackageManager, PackageManagerSpec, PermittedDependencies, SourceBundle, Version,
};
use zk_sca_verifier::{DecodedJournal, decode_journal, verify_receipt};

#[derive(Parser)]
#[clap(
    name = "ZK-SCA CLI",
    version = env!("CARGO_PKG_VERSION"),
    about = "Prove or verify a receipt of software composition analysis",
)]
struct Cli {
    #[clap(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate a receipt for a source .tar.gz archive
    Prove {
        /// Path to the source .tar.gz archive
        #[clap(short = 'a', long = "archive")]
        archive: PathBuf,

        /// Package manager used to resolve archive dependencies (e.g., Cargo)
        #[clap(short = 'm', long = "package-manager")]
        package_manager: String,

        /// Version of the package manager used to resolve archive dependencies (semver)
        #[clap(short = 'v', long = "package-manager-version")]
        package_manager_version: String,

        /// Path to the permitted-dependencies JSON file
        #[clap(short = 'p', long = "permitted-deps")]
        permitted_deps: PathBuf,

        /// One or more permitted license identifiers (space-separated or repeat flag)
        #[clap(long = "allowed-licenses")]
        allowed_licenses: Vec<String>,

        /// Run in RISC0 dev mode (no proof generated)
        #[clap(long = "dev-mode")]
        dev_mode: bool,

        /// Log cycle counts during proving
        #[clap(long = "cycle-report")]
        cycle_report: bool,

        /// Path to write the resulting receipt (overrides default)
        #[clap(long = "output")]
        output: Option<PathBuf>,
    },

    /// Verify an existing receipt and optionally print its journal in JSON
    Verify {
        /// Path to the receipt file
        #[clap(short = 'r', long = "receipt")]
        receipt: PathBuf,

        /// Program image ID used by the prover (64-character hex string)
        #[clap(short = 'i', long = "program-id", value_name = "HEX")]
        program_id: String,

        /// Print the journal contents in JSON format if verification succeeds
        #[clap(short = 'j', long = "print-journal")]
        print_journal: bool,
    },
}

type DynError = Box<dyn std::error::Error>;

fn main() -> Result<(), DynError> {
    let cli = Cli::parse();

    match cli.cmd {
        Cmd::Prove {
            archive,
            package_manager,
            package_manager_version,
            permitted_deps,
            allowed_licenses,
            dev_mode,
            cycle_report,
            output,
        } => prove_cmd(
            &archive,
            &package_manager,
            &package_manager_version,
            &permitted_deps,
            &allowed_licenses,
            dev_mode,
            cycle_report,
            output,
        ),
        Cmd::Verify {
            receipt,
            program_id,
            print_journal,
        } => verify_cmd(&receipt, &program_id, print_journal),
    }
}

fn prove_cmd(
    archive: &PathBuf,
    pm_name: &str,
    pm_version: &str,
    permitted_deps_path: &PathBuf,
    allowed_licenses: &[String],
    dev_mode: bool,
    cycle_report: bool,
    output: Option<PathBuf>,
) -> Result<(), DynError> {
    let output_path = output.unwrap_or_else(|| {
        let fname = archive.file_name().expect("archive needs a filename");
        let base = Path::new(fname)
            .file_stem()
            .and_then(|s| Path::new(s).file_stem())
            .expect("valid UTF-8 filename");
        env::current_dir()
            .expect("cannot read current directory")
            .join(base)
            .with_extension("zk-sca.bin")
    });

    let manager = match pm_name.to_lowercase().as_str() {
        "cargo" => PackageManager::Cargo,
        other => return Err(format!("Unsupported package manager: {other}").into()),
    };

    let manager_version =
        Version::parse(pm_version).map_err(|e| format!("Invalid semver '{pm_version}': {e}"))?;

    let tar_bytes = Arc::<[u8]>::from(fs::read(archive)?);
    let deps_raw = fs::read_to_string(permitted_deps_path)?;
    let permitted_dependencies: PermittedDependencies = serde_json::from_str(&deps_raw)?;

    let license_policy = if allowed_licenses.is_empty() {
        None
    } else {
        let json = serde_json::to_string(&allowed_licenses)?;
        Some(serde_json::from_str::<LicensePolicy>(&json)?)
    };

    let bundle = SourceBundle::new(tar_bytes, PackageManagerSpec::new(manager, manager_version));

    let mut prover = Prover::new()
        .with_bundle(bundle)
        .with_permitted_deps(&permitted_dependencies);

    if let Some(policy) = &license_policy {
        prover = prover.with_license_policy(policy);
    }
    if dev_mode {
        prover = prover.with_dev_mode(true);
    }
    if cycle_report {
        prover = prover.with_cycle_report(true);
    }

    let receipt: Receipt = match prover.prove() {
        Ok(r) => r,
        Err(ProverError::MissingPermittedDependencies) => {
            return Err("--permitted-deps is required".into());
        }
        Err(ProverError::MissingSourceArchive) => return Err("--archive is required".into()),
        Err(e) => return Err(format!("Prover failed: {e}").into()),
    };

    let bytes = bincode::serialize(&receipt)?;
    fs::File::create(&output_path)?.write_all(&bytes)?;

    let program_id_hex = hex::encode(program_id_digest().as_bytes());
    println!("Program ID: {program_id_hex}");

    println!("Success! Receipt written to '{}'", output_path.display());
    Ok(())
}

fn parse_program_id(hex_str: &str) -> Result<Digest, DynError> {
    let bytes = <Vec<u8>>::from_hex(hex_str).map_err(|e| format!("invalid --program-id: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!(
            "invalid --program-id: expected 32 bytes (64 hex chars), got {} bytes",
            bytes.len()
        )
        .into());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(Digest::from(arr))
}

fn verify_cmd(
    receipt_path: &PathBuf,
    program_id: &str,
    print_journal: bool,
) -> Result<(), DynError> {
    let data = fs::read(receipt_path)?;
    let receipt: Receipt = bincode::deserialize(&data)?;

    let image_id = parse_program_id(program_id)?;
    verify_receipt(&receipt, image_id)?;

    if print_journal {
        let decoded: DecodedJournal = decode_journal(&receipt.journal)?;
        let output = serde_json::json!({
            "root_hash": hex::encode(decoded.root_hash),
            "license_policy": decoded.license_policy,
            "permitted_dependencies": decoded.permitted_deps,
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("Receipt verified successfully.");
    }

    Ok(())
}
