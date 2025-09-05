#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScaError {
    DisallowedDependency = 1,
    DisallowedVersion = 2,
    DisallowedLicense = 3,
    UnsupportedLockfileVersion = 4,
    InvalidMerkleArchive = 5,
    UndeclaredLockfileDependency = 6,
    MissingLockfile = 7,
    ManifestLockMismatch = 8,
    InvalidManifestEncoding = 9,
    ManifestParseError = 10,
    InvalidLockfileEncoding = 11,
    LockfileParseError = 12,
    RedundantLockfile = 13,
    InvalidWorkspaceCount = 14,
    UnsupportedPackageManager = 15,
    InconsistentPackageManager = 16,
}
