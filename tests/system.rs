//! Integration tests against the real apk installation (skipped where apk is absent).

use bapk::apk::{self, has_program};
use bapk::exec::SystemRunner;

fn world() -> Vec<String> {
    std::fs::read_to_string("/etc/apk/world")
        .map(|s| bapk::world::parse_world(&s))
        .unwrap_or_default()
}

#[test]
fn loads_real_catalog() {
    if !has_program("apk") {
        eprintln!("apk not available; skipping");
        return;
    }
    let pkgs = apk::load_catalog(&SystemRunner, &world()).expect("catalog loads");
    assert!(!pkgs.is_empty());
    let installed: Vec<_> = pkgs.iter().filter(|p| p.installed).collect();
    assert!(!installed.is_empty(), "some packages are installed");
    assert!(installed.iter().all(|p| p.installed_version.is_some()));
    // apk-tools itself must be installed for this test to run at all.
    let apk_tools = pkgs.iter().find(|p| p.name == "apk-tools").expect("apk-tools present");
    assert!(apk_tools.installed);
    assert!(!apk_tools.description.is_empty());
    // Every world entry that is installed is marked explicit.
    for name in world() {
        if let Some(p) = pkgs.iter().find(|p| p.name == name && p.installed) {
            assert!(p.explicit, "{name} should be explicit");
        }
    }
}

#[test]
fn reads_real_apk_version() {
    if !has_program("apk") {
        return;
    }
    let v = apk::apk_version(&SystemRunner).unwrap();
    assert!(v.starts_with("apk-tools "), "{v}");
}

#[test]
fn binary_prints_version() {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_bapk")).arg("--version").output().unwrap();
    assert!(out.status.success());
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), format!("Bold APK {}", env!("CARGO_PKG_VERSION")));
}
