use anyhow::Result;
use crates_io_api::{CratesQuery, Sort, SyncClient};
use rustsec::{Advisory, Database};
use semver::Version;
use spdx::Expression as SpdxExpr;
use std::{fs, path::PathBuf};
use zk_sca_types::{Dependency, LicenseExpr, PackageManager, PermittedDependencies};

fn main() -> Result<()> {
    let base_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let db_dir = base_dir.join("rustsec-advisory-db");

    // Fail if the advisory DB directory doesn't exist
    if !db_dir.exists() {
        return Err(anyhow::anyhow!(
            "RustSec advisory DB not found at {}",
            db_dir.display()
        ));
    }

    // Open the database (errors if it's not a valid DB)
    let db = Database::open(&db_dir)?;

    // Fail if the DB contains no advisories
    if db.iter().next().is_none() {
        return Err(anyhow::anyhow!(
            "RustSec advisory DB at {} contains no advisories",
            db_dir.display()
        ));
    }

    eprintln!("Loaded {} advisories", db.iter().count());

    let client = SyncClient::new(
        "permitted-deps-generator",
        std::time::Duration::from_secs(1),
    )?;

    let mut query = CratesQuery::default();
    query.set_page(1);
    query.set_page_size(100);
    query.set_sort(Sort::Downloads);
    let page = client.crates(query)?;

    let mut safety_list = Vec::new();
    for krate in page.crates {
        let name = krate.name.clone();
        let full = client.get_crate(&name)?;

        // Gather all advisories for this crate
        let advisories: Vec<&Advisory> = db
            .iter()
            .filter(|adv| adv.metadata.package.as_str() == name.as_str())
            .collect();

        let is_vulnerable = |v: &Version| {
            advisories.iter().any(|adv| {
                !adv.versions.unaffected().iter().any(|r| r.matches(v))
                    && !adv.versions.patched().iter().any(|r| r.matches(v))
            })
        };

        // Collect (API) versions along with their parsed semver, filtering out yanked
        let mut versions: Vec<(crates_io_api::Version, Version)> = full
            .versions
            .into_iter()
            .filter(|v| !v.yanked)
            .filter_map(|v| Version::parse(&v.num).ok().map(|sv| (v, sv)))
            .collect();
        versions.sort_by(|a, b| a.1.cmp(&b.1));

        // Find the first non-vulnerable (i.e. safe) version
        let (min_safe_version, license_expr) = if let Some((v, semver_ver)) = versions
            .iter()
            .find(|(_, semver_ver)| !is_vulnerable(semver_ver))
        {
            // Pull the license from that specific version, if present
            let raw = match &v.license {
                Some(lic) if !lic.trim().is_empty() => lic.as_str(),
                _ => {
                    eprintln!(
                        "warning: version {} of crate {} has no license; skipping",
                        v.num, name,
                    );
                    continue;
                }
            };
            // Convert "MIT/Apache-2.0" to "MIT OR Apache-2.0"
            let spdx_str = raw.replace('/', " OR ");
            // Now parse, panicking loudly on any remaining error
            let expr = SpdxExpr::parse(&spdx_str).unwrap_or_else(|e| {
                panic!(
                    "Failed to parse SPDX expression `{}` (from `{}`) for crate `{}`: {}",
                    spdx_str, raw, name, e
                )
            });
            (semver_ver.clone(), LicenseExpr(expr))
        } else {
            println!("No safe version found for {}. Skipping.", name);
            continue;
        };

        safety_list.push(Dependency::new(name, license_expr, min_safe_version));
    }

    let pd = PermittedDependencies::try_new(PackageManager::Cargo, safety_list)
        .expect("sanity: no duplicates in generated data");

    let out_path = base_dir.join("../../fixtures/permitted-dependencies.json");
    fs::write(&out_path, serde_json::to_string_pretty(&pd).unwrap())?;
    println!("Wrote {}", out_path.display());

    Ok(())
}
