use std::{
    collections::HashMap,
    fs,
    path::Path,
    sync::{LazyLock, Mutex},
};
use zk_sca_guest_abi::PartialMerkleArchive;
use zk_sca_guest_abi_utils::build_merkle_archive;
use zk_sca_types::{
    PackageManager, PackageManagerSpec, PermittedDependencies, SourceBundle, Version,
};

static FIXTURE_CACHE: LazyLock<Mutex<HashMap<String, Vec<u8>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn load_fixture(name: &str) -> Vec<u8> {
    let mut cache = FIXTURE_CACHE.lock().unwrap();
    if let Some(data) = cache.get(name) {
        return data.clone();
    }
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let path = Path::new(manifest_dir)
        .join("..")
        .join("..")
        .join("fixtures")
        .join(name);
    let data = fs::read(&path).unwrap_or_else(|_| panic!("Unable to read fixture {}", name));
    cache.insert(name.to_owned(), data.clone());
    data
}

pub fn load_cargo_bundle(name: &str) -> SourceBundle {
    let tar_gz = load_fixture(name);
    SourceBundle::from_vec(
        tar_gz,
        PackageManagerSpec::new(PackageManager::Cargo, Version::new(1, 82, 0)),
    )
}

// False warning bc not used in end_to_end.rs.
#[allow(dead_code)]
pub fn load_cargo_archive(name: &str) -> PartialMerkleArchive {
    let bundle = load_cargo_bundle(name);
    build_merkle_archive(&bundle).unwrap_or_else(|_| panic!("Fixture parse failed for {}", name))
}

// False warning bc not used in env_conflict.rs.
#[allow(dead_code)]
pub fn load_permitted_deps(name: &str) -> PermittedDependencies {
    let bytes = load_fixture(name);
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| panic!("Unable to parse permitted dependencies {}", name))
}
