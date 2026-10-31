//! Builds the package catalog from `apk query --format json` output.

use std::collections::{HashMap, HashSet};

use anyhow::Result;
use serde::Deserialize;

use crate::models::{Package, Repo};

/// One package record as emitted by `apk query --format json`.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case", default)]
pub struct QueryRecord {
    pub name: String,
    pub version: String,
    pub description: String,
    pub url: String,
    pub license: String,
    pub origin: String,
    pub maintainer: String,
    pub file_size: u64,
    pub installed_size: u64,
    pub depends: Vec<String>,
    pub repositories: Vec<String>,
    pub status: Vec<String>,
}

/// The `--fields` argument bapk requests from `apk query`.
pub const QUERY_FIELDS: &str =
    "name,version,description,url,license,origin,maintainer,file-size,installed-size,depends,repositories";

/// Parses the JSON array printed by `apk query --format json`.
pub fn parse_records(json: &str) -> Result<Vec<QueryRecord>> {
    if json.trim().is_empty() {
        return Ok(Vec::new());
    }
    Ok(serde_json::from_str(json)?)
}

/// Merges query results into the unified package list, sorted by name.
pub fn merge(
    available: Vec<QueryRecord>,
    installed: Vec<QueryRecord>,
    upgradable: &HashSet<String>,
    world: &[String],
) -> Vec<Package> {
    let installed_versions: HashMap<String, String> = installed
        .iter()
        .map(|r| (r.name.clone(), r.version.clone()))
        .collect();
    let world: HashSet<&str> = world.iter().map(String::as_str).collect();

    let mut seen = HashSet::new();
    let mut packages = Vec::new();
    let available_names: HashSet<String> = available.iter().map(|r| r.name.clone()).collect();
    let local = installed.into_iter().filter(|r| !available_names.contains(&r.name));
    for record in available.into_iter().chain(local) {
        if !seen.insert(record.name.clone()) {
            continue;
        }
        let installed_version = installed_versions.get(&record.name).cloned();
        packages.push(Package {
            repo: Repo::from_repositories(&record.repositories),
            installed: installed_version.is_some(),
            upgradable: upgradable.contains(&record.name),
            explicit: world.contains(record.name.as_str()),
            installed_version,
            name: record.name,
            version: record.version,
            description: record.description,
            url: record.url,
            license: record.license,
            origin: record.origin,
            maintainer: record.maintainer,
            file_size: record.file_size,
            installed_size: record.installed_size,
            depends: record.depends,
        });
    }
    packages.sort_by(|a, b| a.name.cmp(&b.name));
    packages
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"[
      {
        "name": "btop",
        "version": "1.4.6-r0",
        "description": "Resource monitor",
        "arch": "aarch64",
        "license": "Apache-2.0",
        "origin": "btop",
        "url": "https://github.com/aristocratos/btop",
        "maintainer": "Someone <a@b.c>",
        "file-size": 630358,
        "installed-size": 1480846,
        "depends": ["so:libc.musl-aarch64.so.1", "so:libstdc++.so.6"],
        "repositories": ["lib/apk/db/installed", "https://dl-cdn.alpinelinux.org/alpine/v3.24/community"],
        "status": ["installed"]
      }, {
        "name": "zsh",
        "version": "5.9-r7"
      }
    ]"#;

    fn rec(name: &str, version: &str, repo: &str) -> QueryRecord {
        QueryRecord {
            name: name.into(),
            version: version.into(),
            repositories: vec![repo.into()],
            ..Default::default()
        }
    }

    const MAIN: &str = "https://mirror/alpine/v3.24/main";
    const DB: &str = "lib/apk/db/installed";

    #[test]
    fn parses_full_record() {
        let recs = parse_records(SAMPLE).unwrap();
        assert_eq!(recs.len(), 2);
        let b = &recs[0];
        assert_eq!(b.name, "btop");
        assert_eq!(b.version, "1.4.6-r0");
        assert_eq!(b.description, "Resource monitor");
        assert_eq!(b.license, "Apache-2.0");
        assert_eq!(b.origin, "btop");
        assert_eq!(b.url, "https://github.com/aristocratos/btop");
        assert_eq!(b.maintainer, "Someone <a@b.c>");
        assert_eq!(b.file_size, 630358);
        assert_eq!(b.installed_size, 1480846);
        assert_eq!(b.depends.len(), 2);
        assert_eq!(b.repositories.len(), 2);
        assert_eq!(b.status, vec!["installed"]);
    }

    #[test]
    fn missing_fields_default() {
        let recs = parse_records(SAMPLE).unwrap();
        assert_eq!(recs[1].description, "");
        assert!(recs[1].depends.is_empty());
        assert_eq!(recs[1].file_size, 0);
    }

    #[test]
    fn empty_output_is_empty_list() {
        assert!(parse_records("").unwrap().is_empty());
        assert!(parse_records("  \n").unwrap().is_empty());
        assert!(parse_records("[]").unwrap().is_empty());
    }

    #[test]
    fn invalid_json_is_error() {
        assert!(parse_records("[{").is_err());
    }

    #[test]
    fn merge_available_only() {
        let mut r = rec("curl", "8.0-r0", MAIN);
        r.description = "url tool".into();
        r.installed_size = 42;
        let pkgs = merge(vec![r], vec![], &HashSet::new(), &[]);
        assert_eq!(pkgs.len(), 1);
        let p = &pkgs[0];
        assert_eq!(p.name, "curl");
        assert_eq!(p.version, "8.0-r0");
        assert_eq!(p.description, "url tool");
        assert_eq!(p.installed_size, 42);
        assert_eq!(p.repo, Repo::Main);
        assert!(!p.installed);
        assert_eq!(p.installed_version, None);
        assert!(!p.upgradable);
        assert!(!p.explicit);
    }

    #[test]
    fn merge_marks_installed_with_installed_version() {
        let pkgs = merge(
            vec![rec("curl", "8.1-r0", MAIN)],
            vec![rec("curl", "8.0-r0", DB)],
            &HashSet::new(),
            &[],
        );
        assert!(pkgs[0].installed);
        assert_eq!(pkgs[0].installed_version.as_deref(), Some("8.0-r0"));
        assert_eq!(pkgs[0].version, "8.1-r0");
    }

    #[test]
    fn merge_marks_upgradable_and_explicit() {
        let up: HashSet<String> = ["curl".to_string()].into();
        let pkgs = merge(
            vec![rec("curl", "8.1-r0", MAIN), rec("git", "2.0-r0", MAIN)],
            vec![rec("curl", "8.0-r0", DB), rec("git", "2.0-r0", DB)],
            &up,
            &["git".to_string()],
        );
        assert!(pkgs[0].upgradable);
        assert!(!pkgs[0].explicit);
        assert!(!pkgs[1].upgradable);
        assert!(pkgs[1].explicit);
    }

    #[test]
    fn merge_includes_installed_packages_missing_from_repositories() {
        let mut local = rec("mytool", "0.1-r0", DB);
        local.description = "home built".into();
        let pkgs = merge(vec![rec("curl", "8.0-r0", MAIN)], vec![local], &HashSet::new(), &[]);
        assert_eq!(pkgs.len(), 2);
        let m = pkgs.iter().find(|p| p.name == "mytool").unwrap();
        assert_eq!(m.repo, Repo::Local);
        assert!(m.installed);
        assert_eq!(m.installed_version.as_deref(), Some("0.1-r0"));
        assert_eq!(m.version, "0.1-r0");
        assert_eq!(m.description, "home built");
    }

    #[test]
    fn merge_sorts_by_name_and_dedupes() {
        let pkgs = merge(
            vec![rec("zsh", "1", MAIN), rec("bash", "1", MAIN), rec("bash", "2", MAIN)],
            vec![rec("mytool", "1", DB)],
            &HashSet::new(),
            &[],
        );
        let names: Vec<&str> = pkgs.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, vec!["bash", "mytool", "zsh"]);
        assert_eq!(pkgs[0].version, "1");
    }
}
