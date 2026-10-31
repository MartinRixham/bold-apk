//! Vulnerability lookups against the Alpine security database (secdb.alpinelinux.org).

use std::collections::HashMap;

use anyhow::Result;
use serde::Deserialize;

use crate::version;

#[derive(Deserialize)]
struct RawDb {
    #[serde(default)]
    packages: Vec<RawEntry>,
}

#[derive(Deserialize)]
struct RawEntry {
    pkg: RawPkg,
}

#[derive(Deserialize)]
struct RawPkg {
    name: String,
    #[serde(default)]
    secfixes: HashMap<String, Vec<String>>,
}

/// A known vulnerability affecting a package version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vulnerability {
    pub id: String,
    pub fixed_in: String,
}

/// Security fixes indexed by origin (source package) name.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SecDb {
    fixes: HashMap<String, Vec<(String, Vec<String>)>>,
}

impl SecDb {
    /// Parses one secdb JSON document (e.g. `v3.24/main.json`).
    pub fn parse(json: &str) -> Result<SecDb> {
        let raw: RawDb = serde_json::from_str(json)?;
        let mut db = SecDb::default();
        for entry in raw.packages {
            let fixes = db.fixes.entry(entry.pkg.name).or_default();
            fixes.extend(entry.pkg.secfixes);
        }
        Ok(db)
    }

    /// Merges another database into this one.
    pub fn extend(&mut self, other: SecDb) {
        for (origin, fixes) in other.fixes {
            self.fixes.entry(origin).or_default().extend(fixes);
        }
    }

    /// Vulnerabilities fixed in versions newer than `version` of `origin`.
    pub fn vulnerabilities(&self, origin: &str, version: &str) -> Vec<Vulnerability> {
        let Some(fixes) = self.fixes.get(origin) else {
            return Vec::new();
        };
        fixes
            .iter()
            .filter(|(fixed_in, _)| fixed_in != "0")
            .filter(|(fixed_in, _)| version::compare(version, fixed_in).is_lt())
            .flat_map(|(fixed_in, ids)| {
                ids.iter().map(move |id| Vulnerability {
                    id: id.clone(),
                    fixed_in: fixed_in.clone(),
                })
            })
            .collect()
    }
}

/// Maps the contents of /etc/alpine-release to the secdb branch name.
pub fn branch_for_release(release: &str) -> String {
    let release = release.trim();
    if release.is_empty() || release.contains('_') {
        return "edge".into();
    }
    let mut parts = release.split('.');
    match (parts.next(), parts.next()) {
        (Some(major), Some(minor)) => format!("v{major}.{minor}"),
        _ => "edge".into(),
    }
}

/// The secdb URLs to fetch for a branch.
pub fn urls_for_branch(branch: &str) -> Vec<String> {
    ["main", "community"]
        .iter()
        .map(|repo| format!("https://secdb.alpinelinux.org/{branch}/{repo}.json"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAIN: &str = r#"{"reponame":"main","distroversion":"v3.24","packages":[
        {"pkg":{"name":"openssl","secfixes":{
            "0":["CVE-2022-1292"],
            "3.0.1-r0":["CVE-2021-4044"],
            "3.5.4-r0":["CVE-2025-9230","CVE-2025-9231"]}}},
        {"pkg":{"name":"zlib","secfixes":{"1.2.12-r0":["CVE-2018-25032"]}}}
    ]}"#;

    const COMMUNITY: &str = r#"{"packages":[
        {"pkg":{"name":"7zip","secfixes":{"26.01-r0":["CVE-2026-48092"]}}}
    ]}"#;

    fn ids(v: &[Vulnerability]) -> Vec<&str> {
        let mut ids: Vec<&str> = v.iter().map(|v| v.id.as_str()).collect();
        ids.sort();
        ids
    }

    #[test]
    fn old_version_has_open_vulnerabilities() {
        let db = SecDb::parse(MAIN).unwrap();
        let v = db.vulnerabilities("openssl", "3.0.0-r0");
        assert_eq!(
            ids(&v),
            vec!["CVE-2021-4044", "CVE-2025-9230", "CVE-2025-9231"]
        );
        let fix = v.iter().find(|v| v.id == "CVE-2021-4044").unwrap();
        assert_eq!(fix.fixed_in, "3.0.1-r0");
    }

    #[test]
    fn fixed_version_is_clean() {
        let db = SecDb::parse(MAIN).unwrap();
        assert!(db.vulnerabilities("openssl", "3.5.4-r0").is_empty());
        assert!(db.vulnerabilities("openssl", "3.6.0-r0").is_empty());
    }

    #[test]
    fn partially_fixed_version() {
        let db = SecDb::parse(MAIN).unwrap();
        let v = db.vulnerabilities("openssl", "3.1.0-r0");
        assert_eq!(ids(&v), vec!["CVE-2025-9230", "CVE-2025-9231"]);
    }

    #[test]
    fn zero_version_entries_are_never_reported() {
        let db = SecDb::parse(MAIN).unwrap();
        let v = db.vulnerabilities("openssl", "0.1-r0");
        assert!(!v.iter().any(|v| v.id == "CVE-2022-1292"));
    }

    #[test]
    fn unknown_package_is_clean() {
        let db = SecDb::parse(MAIN).unwrap();
        assert!(db.vulnerabilities("nonexistent", "1.0-r0").is_empty());
    }

    #[test]
    fn extend_merges_repositories() {
        let mut db = SecDb::parse(MAIN).unwrap();
        db.extend(SecDb::parse(COMMUNITY).unwrap());
        assert_eq!(db.vulnerabilities("7zip", "25.0-r0").len(), 1);
        assert_eq!(db.vulnerabilities("zlib", "1.2.11-r0").len(), 1);
    }

    #[test]
    fn invalid_json_is_error() {
        assert!(SecDb::parse("{").is_err());
    }

    #[test]
    fn branch_from_stable_release() {
        assert_eq!(branch_for_release("3.24.3\n"), "v3.24");
        assert_eq!(branch_for_release("3.9.0"), "v3.9");
    }

    #[test]
    fn branch_from_edge_release() {
        assert_eq!(branch_for_release("3.25_alpha20260101"), "edge");
        assert_eq!(branch_for_release(""), "edge");
    }

    #[test]
    fn urls_cover_main_and_community() {
        assert_eq!(
            urls_for_branch("v3.24"),
            vec![
                "https://secdb.alpinelinux.org/v3.24/main.json",
                "https://secdb.alpinelinux.org/v3.24/community.json",
            ]
        );
    }
}
