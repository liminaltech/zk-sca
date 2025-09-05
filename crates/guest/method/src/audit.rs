extern crate alloc;

use crate::cargo::{ResolvedDependencies, ResolvedDependency};
use alloc::{format, string::String};
use hashbrown::HashMap;
use zk_sca_guest_abi::{Dependency, LicensePolicy, NonEmpty, ScaError};

/// Audits resolved dependencies against an allowlist and optional license policy,
/// erroring out on the first non-compliant package.
pub fn audit_dependencies(
    resolved: &ResolvedDependencies,
    allowlist: &NonEmpty<Dependency>,
    license_policy: Option<&LicensePolicy>,
) -> Result<(), (ScaError, String)> {
    let allow_by_pkg: HashMap<&str, &Dependency> =
        allowlist.iter().map(|d| (d.name(), d)).collect();

    for dep in resolved {
        enforce_policies(dep, &allow_by_pkg, license_policy)?;
    }

    Ok(())
}

/// Check a single [`ResolvedDependency`] against the allowlist and licence policy.
fn enforce_policies(
    dep: &ResolvedDependency,
    allow_by_pkg: &HashMap<&str, &Dependency>,
    license_policy: Option<&LicensePolicy>,
) -> Result<(), (ScaError, String)> {
    let safe = allow_by_pkg.get(dep.name.as_str()).ok_or_else(|| {
        (
            ScaError::DisallowedDependency,
            format!("{} not permitted", dep.name),
        )
    })?;

    if let Some(policy) = license_policy {
        if !safe.license().evaluate(|r| policy.contains(r)) {
            return Err((
                ScaError::DisallowedLicense,
                format!("{} (via {}) not permitted", dep.name, dep.provenance),
            ));
        }
    }

    if &dep.version < safe.min_safe_version() {
        return Err((
            ScaError::DisallowedVersion,
            format!(
                "{}@{} < min {}",
                dep.name,
                dep.version,
                safe.min_safe_version()
            ),
        ));
    }

    Ok(())
}
