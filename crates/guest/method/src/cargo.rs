extern crate alloc;

use alloc::{
    borrow::ToOwned,
    collections::BTreeMap,
    format,
    string::{String, ToString},
    vec::Vec,
};
use cargo_lock::{Lockfile, ResolveVersion};
use cargo_manifest::{Dependency as ManifestDep, Manifest};
use core::hash::Hash;
use hashbrown::{HashMap, HashSet};
use semver::{Version, VersionReq};
use zk_sca_guest_abi::ScaError;
use zk_sca_guest_abi_utils::{ValidPartialArchive, ValidatedFile};

/// Fully‑resolved, version‑pinned dependency.
#[derive(Debug, Clone)]
pub struct ResolvedDependency {
    pub name: String,
    pub version: Version,
    /// Path of the lockfile that pinned this dependency
    pub provenance: String,
}

/// Flat list produced by [`validate_cargo_archive`].
pub type ResolvedDependencies = Vec<ResolvedDependency>;

/// Validate all Cargo metadata contained in a Merklized TAR archive and
/// return a flattened list of fully-resolved external dependencies.
///
/// Invariants enforced:
/// 1. Exactly one Cargo workspace--implicit or explicit--is present.
/// 2. The workspace root has a single `Cargo.lock`.
/// 3. Every direct dependency declared in any `Cargo.toml`—including build/dev
///    deps and rename syntax—is satisfied by at least one package version in
///    the workspace lockfile.
/// 4. Every package listed in every `Cargo.lock` is reachable from at least one
///    workspace member via the dependency graph encoded in that lockfile.
/// 5. All lockfiles are version 3 or 4 (older formats may lack required metadata).
///
/// On success, returns `ResolvedDependencies`.
pub fn validate_cargo_archive(
    archive: &ValidPartialArchive,
) -> Result<ResolvedDependencies, (ScaError, String)> {
    let manifests: Vec<ManifestInfo> = archive
        .files
        .iter()
        .filter(|vf| vf.header.name.ends_with("Cargo.toml"))
        .map(parse_manifest_file)
        .collect::<Result<_, _>>()?;

    let workspace_root_manifest_path = ensure_single_workspace(&manifests)?;

    let locks: Vec<LockInfo> = archive
        .files
        .iter()
        .filter(|vf| vf.header.name.ends_with("Cargo.lock"))
        .map(parse_lock_file)
        .collect::<Result<_, _>>()?;
    let manifest_by_path: HashMap<String, ManifestInfo> =
        map_by(manifests.clone(), |m| m.path.clone());
    let lock_by_path: HashMap<String, LockInfo> = map_by(locks, |l| l.path.clone());

    // Member crates must not have their own lockfile.
    for (path, manifest) in &manifest_by_path {
        if !manifest.has_workspace {
            let own_lock = to_lock_path(path);
            if lock_by_path.contains_key(&own_lock) {
                return Err((
                    ScaError::RedundantLockfile,
                    format!("crate `{path}` unexpectedly has its own Cargo.lock"),
                ));
            }
        }
    }
    let workspace_lock_path = to_lock_path(workspace_root_manifest_path);
    let workspace_lock = lock_by_path.get(&workspace_lock_path).ok_or_else(|| {
        (
            ScaError::MissingLockfile,
            format!(
                "workspace root `{workspace_root_manifest_path}` has no `{workspace_lock_path}`"
            ),
        )
    })?;

    // Ensure that every declared dep's requirements are met by the lockfile.
    for manifest in manifest_by_path.values() {
        ensure_declared_reqs_are_satisfied(manifest, workspace_lock)?;
    }

    // Ensure that no external deps in lockfile are unreachable by a declared dep.
    for lock in lock_by_path.values() {
        ensure_lock_graph_is_reachable(lock)?;
    }

    // Produce flattened list of external deps.
    let mut resolved: ResolvedDependencies = Vec::new();
    for lock in lock_by_path.values() {
        for (pkg, ver) in &lock.pkgs {
            if lock.path_pkgs.contains(pkg) {
                continue;
            }
            resolved.push(ResolvedDependency {
                name: pkg.clone(),
                version: ver.clone(),
                provenance: lock.path.clone(),
            });
        }
    }

    Ok(resolved)
}

#[derive(Debug, Clone)]
struct ManifestInfo {
    path: String,
    deps: HashMap<String, VersionReq>,
    has_workspace: bool,
    workspace_members: Option<Vec<String>>,
    workspace_excludes: Option<Vec<String>>,
}

#[derive(Debug, Clone)]
struct LockInfo {
    path: String,
    pkgs: HashMap<String, Version>,
    deps: HashMap<String, Vec<String>>,
    path_pkgs: HashSet<String>,
}

fn ensure_single_workspace<'a>(
    manifests: &'a [ManifestInfo],
) -> Result<&'a str, (ScaError, String)> {
    let explicit_roots: Vec<&ManifestInfo> = manifests.iter().filter(|m| m.has_workspace).collect();

    let mut root_paths: HashSet<&'a str> = HashSet::with_capacity(manifests.len());
    for manifest in manifests {
        // A manifest containing `[workspace]` is itself a root.
        if manifest.has_workspace {
            root_paths.insert(manifest.path.as_str());
            continue;
        }

        // Check if any explicit root claims this manifest.
        let mut owner: Option<&'a str> = None;
        for root in &explicit_roots {
            if workspace_owns_manifest(root, manifest) {
                owner = Some(root.path.as_str());
                break;
            }
        }

        match owner {
            // Explicit workspace matched.
            Some(root_path) => {
                root_paths.insert(root_path);
            }
            // Not covered, implicit workspace.
            None => {
                root_paths.insert(manifest.path.as_str());
            }
        }
    }

    let workspace_count = root_paths.len();
    if workspace_count != 1 {
        return Err((
            ScaError::InvalidWorkspaceCount,
            format!("archive contains {workspace_count} Cargo workspaces; exactly one required"),
        ));
    }

    let sole_root = *root_paths.iter().next().unwrap();
    Ok(sole_root)
}

/// Returns `true` if `manifest` is a member of the explicit workspace `root`.
fn workspace_owns_manifest(root: &ManifestInfo, manifest: &ManifestInfo) -> bool {
    let root_dir = root.path.trim_end_matches("Cargo.toml");
    if !manifest.path.starts_with(root_dir) {
        return false;
    }

    // Respect `exclude` first.
    if let Some(excludes) = &root.workspace_excludes {
        for excl in excludes {
            let excl_prefix = format!("{}{}", root_dir, excl.trim_end_matches('/'));
            if manifest.path.starts_with(&excl_prefix) {
                return false;
            }
        }
    }

    match &root.workspace_members {
        Some(members) if !members.is_empty() => {
            for member in members {
                let member_prefix = format!("{}{}", root_dir, member.trim_end_matches('/'));
                if manifest.path.starts_with(&member_prefix) {
                    return true;
                }
            }
            false
        }
        // `[workspace]` with an empty `members = []` list owns nothing.
        Some(_) => false,
        // No `members` key is wildcard: owns every crate under root not excluded.
        None => true,
    }
}

/// Parse a `Cargo.toml` and collect dependency requirements.
fn parse_manifest_file(vf: &ValidatedFile) -> Result<ManifestInfo, (ScaError, String)> {
    let text = core::str::from_utf8(&vf.bytes).map_err(|_| {
        (
            ScaError::InvalidManifestEncoding,
            format!("`{}` is not valid UTF‑8", vf.header.name),
        )
    })?;

    let manifest: Manifest = Manifest::from_slice(text.as_bytes()).map_err(|e| {
        (
            ScaError::ManifestParseError,
            format!("Failed to parse `{}`: {e}", vf.header.name),
        )
    })?;

    // Collect all direct requirements (including build & dev) using canonical package name.
    let mut deps = HashMap::new();
    if let Some(tbl) = manifest.dependencies.clone() {
        merge_deps(&mut deps, tbl);
    }
    if let Some(tbl) = manifest.build_dependencies.clone() {
        merge_deps(&mut deps, tbl);
    }
    if let Some(tbl) = manifest.dev_dependencies.clone() {
        merge_deps(&mut deps, tbl);
    }

    // Workspace membership & exclusions, preserving Cargo semantics.
    let (members_opt, excludes_opt) = manifest.workspace.as_ref().map_or((None, None), |ws| {
        let members_opt = Some(ws.members.clone());
        let excludes_opt = ws.exclude.clone().filter(|v| !v.is_empty());
        (members_opt, excludes_opt)
    });

    Ok(ManifestInfo {
        path: vf.header.name.clone(),
        deps,
        has_workspace: manifest.workspace.is_some(),
        workspace_members: members_opt,
        workspace_excludes: excludes_opt,
    })
}

/// Parse a `Cargo.lock` and produce maps for packages and their dependencies.
fn parse_lock_file(vf: &ValidatedFile) -> Result<LockInfo, (ScaError, String)> {
    let text = core::str::from_utf8(&vf.bytes).map_err(|_| {
        (
            ScaError::InvalidLockfileEncoding,
            format!("`{}` is not valid UTF‑8", vf.header.name),
        )
    })?;

    let lockfile: Lockfile = text.parse().map_err(|e| {
        (
            ScaError::LockfileParseError,
            format!("Failed to parse `{}`: {e}", vf.header.name),
        )
    })?;

    // Require Cargo.lock v3 or v4 because v1/v2 may lack transitive deps’ source/checksum.
    if lockfile.version != ResolveVersion::V3 && lockfile.version != ResolveVersion::V4 {
        return Err((
            ScaError::UnsupportedLockfileVersion,
            "Unsupported Cargo.lock version (expected 3 or 4)".to_string(),
        ));
    }

    let mut pkgs = HashMap::with_capacity(lockfile.packages.len());
    let mut deps: HashMap<String, Vec<String>> = HashMap::new();
    let mut path_pkgs: HashSet<String> = HashSet::new();

    for pkg in lockfile.packages {
        let name = pkg.name.to_string();
        pkgs.insert(name.clone(), pkg.version.clone());
        let dep_names = pkg
            .dependencies
            .into_iter()
            .map(|d| d.name.to_string())
            .collect::<Vec<_>>();
        deps.insert(name.clone(), dep_names);
        if pkg.source.is_none() {
            path_pkgs.insert(name);
        }
    }

    Ok(LockInfo {
        path: vf.header.name.clone(),
        pkgs,
        deps,
        path_pkgs,
    })
}

/// Checks that every declared dependency requirement in `manifest` is
/// satisfied by some package version in `lock`.
fn ensure_declared_reqs_are_satisfied(
    manifest: &ManifestInfo,
    lock: &LockInfo,
) -> Result<(), (ScaError, String)> {
    for (pkg, req) in &manifest.deps {
        match lock.pkgs.get(pkg) {
            Some(ver) if req.matches(ver) => {}
            _ => {
                return Err((
                    ScaError::ManifestLockMismatch,
                    format!(
                        "Requirement `{}` {} not satisfied by {}",
                        pkg, req, lock.path
                    ),
                ));
            }
        }
    }
    Ok(())
}

/// Ensures that each dependency in a lockfile is reachable from at least one
/// workspace member via the graph encoded in the lockfile.
fn ensure_lock_graph_is_reachable(lock: &LockInfo) -> Result<(), (ScaError, String)> {
    let mut stack: Vec<&String> = lock.path_pkgs.iter().collect();
    let mut seen: HashSet<&String> = HashSet::new();

    while let Some(pkg) = stack.pop() {
        if !seen.insert(pkg) {
            continue;
        }
        if let Some(children) = lock.deps.get(pkg) {
            for child in children {
                stack.push(child);
            }
        }
    }

    // Any package not visited is undeclared.
    for pkg in lock.pkgs.keys() {
        if !seen.contains(pkg) {
            return Err((
                ScaError::UndeclaredLockfileDependency,
                format!(
                    "dependency `{}` in {} is not reachable from workspace roots",
                    pkg, lock.path
                ),
            ));
        }
    }
    Ok(())
}

fn merge_deps(target: &mut HashMap<String, VersionReq>, src: BTreeMap<String, ManifestDep>) {
    for (user_key, dep) in src {
        let canonical = dep.package().unwrap_or(&user_key).to_string();
        let req_str = dep.req().to_owned();
        if let Ok(req) = VersionReq::parse(&req_str) {
            target.insert(canonical, req);
        }
    }
}

fn map_by<K, V, F>(items: Vec<V>, key_fn: F) -> HashMap<K, V>
where
    K: Eq + Hash,
    F: Fn(&V) -> K,
{
    let mut out = HashMap::with_capacity(items.len());
    for item in items {
        out.insert(key_fn(&item), item);
    }
    out
}

#[inline]
fn to_lock_path(manifest_path: &str) -> String {
    manifest_path.trim_end_matches("Cargo.toml").to_owned() + "Cargo.lock"
}
