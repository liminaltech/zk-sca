#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum ProverError {
    #[error("dependency is not in list permitted: {0}")]
    DisallowedDependency(String),
    #[error("dependency version is below the permitted minimum: {0}")]
    DisallowedVersion(String),
    #[error("dependency license is not on the allow-list: {0}")]
    DisallowedLicense(String),
    #[error("lockfile version is unsupported: {0}")]
    UnsupportedLockfileVersion(String),
    #[error("Merkle archive is malformed or proofs don’t verify: {0}")]
    InvalidMerkleArchive(String),
    #[error("manifest found with no matching lockfile: {0}")]
    MissingLockfile(String),
    #[error("lockfile found with no matching manifest: {0}")]
    MissingManifest(String),
    #[error("manifest and lockfile contents do not match w.r.t. requirements: {0}")]
    ManifestLockMismatch(String),
    #[error("undeclared dependency in lockfile not reachable from workspace roots: {0}")]
    UndeclaredLockfileDependency(String),
    #[error("invalid manifest encoding: {0}")]
    InvalidManifestEncoding(String),
    #[error("manifest parse error: {0}")]
    ManifestParseError(String),
    #[error("invalid lockfile encoding: {0}")]
    InvalidLockfileEncoding(String),
    #[error("lockfile parse error: {0}")]
    LockfileParseError(String),
    #[error("redundant lockfile found for crate: {0}")]
    RedundantLockfile(String),
    #[error("invalid workspace count: {0}")]
    InvalidWorkspaceCount(String),
    #[error("unsupported package manager: {0}")]
    UnsupportedPackageManager(String),
    #[error("inconsistent package manager between archive and permitted deps: {0}")]
    InconsistentPackageManager(String),
    #[error("failed to convert archive into Merkle tree: {0}")]
    ArchiveParseError(String),
    #[error("failed to execute prover (unknown guest error {0}): {1}")]
    UnknownGuestError(u32, String),
    #[error("permitted dependencies must be provided")]
    MissingPermittedDependencies,
    #[error("source archive must be provided")]
    MissingSourceArchive,
    #[error("environment variable `{0}` was already set to “{1}” but option was false")]
    EnvVarConflict(String, String),
}
