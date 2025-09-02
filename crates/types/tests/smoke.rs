use zk_sca_types::{
    Dependency, LicenseExpr, LicensePolicy, PackageManager, PackageManagerSpec,
    PermittedDependencies, SourceBundle, TypesError, Version,
};

#[test]
fn smoke_basic_constructors() {
    // Dependency
    let dep = Dependency::new(
        "foo".into(),
        LicenseExpr(spdx::Expression::parse("MIT").unwrap()),
        Version::new(1, 2, 3),
    );
    assert_eq!(dep.name(), "foo");
    assert_eq!(dep.license().to_string(), "MIT");
    assert_eq!(dep.min_safe_version(), &Version::new(1, 2, 3));

    // PackageManagerSpec
    let spec = PackageManagerSpec::new(PackageManager::Cargo, Version::new(0, 1, 0));
    assert_eq!(spec.manager(), PackageManager::Cargo);
    assert_eq!(spec.version(), &Version::new(0, 1, 0));

    // SourceBundle
    let bundle = SourceBundle::from_vec(vec![0u8], spec.clone());
    assert_eq!(bundle.tar_gz(), &[0u8]);
    assert_eq!(bundle.resolved_with().manager(), PackageManager::Cargo);

    // PermittedDependencies
    let ok = PermittedDependencies::try_new(PackageManager::Cargo, vec![dep.clone()]);
    assert!(ok.is_ok());
    let pd = ok.unwrap();
    assert_eq!(pd.resolvable_with(), PackageManager::Cargo);
    assert_eq!(pd.dependencies().iter().count(), 1);

    // PermittedDependencies
    let dup = PermittedDependencies::try_new(PackageManager::Cargo, vec![dep.clone(), dep.clone()]);
    assert!(dup.is_err());

    // TypesError
    let ve = TypesError::Validation("bad".into());
    assert_eq!(ve.to_string(), "validation failed: bad");
    let pe = spdx::Expression::parse("not-a-license").unwrap_err();
    let le: TypesError = pe.into();
    assert!(matches!(le, TypesError::LicenseParse(_)));

    // LicensePolicy
    let expr = spdx::Expression::parse("MIT").unwrap();
    let req = expr.requirements().next().unwrap().req.clone();
    let policy = LicensePolicy::try_new(vec![req.clone()]).unwrap();
    assert!(policy.contains(&req));

    let dup_pol = LicensePolicy::try_new(vec![req.clone(), req.clone()]);
    assert!(dup_pol.is_err());
}
