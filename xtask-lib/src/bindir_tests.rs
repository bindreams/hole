use crate::bindir::*;

#[skuld::test]
fn dest_names_per_os_are_exact() {
    // Exact-equality is intentional: adding a BINDIR file forces an update
    // here AND in every installer manifest (caught by the conformance tests).
    assert_eq!(
        bindir_dest_names(Os::Windows),
        vec![
            "hole.exe",
            "hole.pdb",
            "ex-ray.exe",
            "galoshes.exe",
            "wintun.dll",
            "NOTICES.md"
        ]
    );
    assert_eq!(
        bindir_dest_names(Os::Darwin),
        vec!["hole", "hole.dSYM", "ex-ray", "galoshes", "NOTICES.md"]
    );
    assert_eq!(
        bindir_dest_names(Os::Linux),
        vec!["hole", "ex-ray", "galoshes", "NOTICES.md"]
    );
}

#[skuld::test]
fn plugin_sidecars_are_ex_ray_and_galoshes() {
    assert_eq!(plugin_sidecar_names(), &["ex-ray", "galoshes"]);
}
