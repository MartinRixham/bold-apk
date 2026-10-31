//! apk command construction, privilege handling and catalog loading.

use std::collections::HashSet;

use anyhow::Result;

use crate::catalog::{self, QUERY_FIELDS};
use crate::exec::Runner;
use crate::models::Package;

/// How privileged apk commands are executed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Privilege {
    Root,
    Doas,
    Sudo,
    Unavailable,
}

impl Privilege {
    /// Picks a privilege strategy. doas is preferred as it is Alpine's default.
    pub fn detect(uid: u32, has_program: impl Fn(&str) -> bool) -> Privilege {
        if uid == 0 {
            Privilege::Root
        } else if has_program("doas") {
            Privilege::Doas
        } else if has_program("sudo") {
            Privilege::Sudo
        } else {
            Privilege::Unavailable
        }
    }

    fn tool(&self) -> Option<&'static str> {
        match self {
            Privilege::Doas => Some("doas"),
            Privilege::Sudo => Some("sudo"),
            Privilege::Root | Privilege::Unavailable => None,
        }
    }

    /// Prefixes a command with the escalation tool. Non-interactive mode passes `-n`
    /// so the tool fails instead of prompting for a password.
    pub fn wrap(&self, argv: Vec<String>, interactive: bool) -> Vec<String> {
        let Some(tool) = self.tool() else {
            return argv;
        };
        let mut wrapped = vec![tool.to_string()];
        if !interactive {
            wrapped.push("-n".into());
        }
        wrapped.extend(argv);
        wrapped
    }

    /// Command that succeeds only if privileged commands can run without a prompt.
    pub fn check_argv(&self) -> Option<Vec<String>> {
        self.tool()
            .map(|tool| vec![tool.into(), "-n".into(), "true".into()])
    }
}

/// The current effective user id.
pub fn current_uid() -> u32 {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata("/proc/self")
        .map(|m| m.uid())
        .unwrap_or(u32::MAX)
}

/// True if `program` is found in PATH.
pub fn has_program(program: &str) -> bool {
    use std::os::unix::fs::PermissionsExt;
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&path).any(|dir| {
        std::fs::metadata(dir.join(program))
            .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    })
}

/// A package operation that modifies the system.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Operation {
    Install(String),
    Remove(String),
    Upgrade(String),
    UpgradeAll,
    UpdateIndex,
}

impl Operation {
    /// The apk command line for this operation (without privilege escalation).
    pub fn argv(&self) -> Vec<String> {
        let mut argv = vec!["apk".to_string(), "--no-progress".to_string()];
        let rest: Vec<&str> = match self {
            Operation::Install(name) => vec!["add", name],
            Operation::Remove(name) => vec!["del", name],
            Operation::Upgrade(name) => vec!["add", "--upgrade", name],
            Operation::UpgradeAll => vec!["upgrade"],
            Operation::UpdateIndex => vec!["update"],
        };
        argv.extend(rest.into_iter().map(String::from));
        argv
    }

    /// Present participle, e.g. "Installing".
    pub fn verb(&self) -> &'static str {
        match self {
            Operation::Install(_) => "Installing",
            Operation::Remove(_) => "Removing",
            Operation::Upgrade(_) | Operation::UpgradeAll => "Upgrading",
            Operation::UpdateIndex => "Updating",
        }
    }

    /// Past tense, e.g. "Installed".
    pub fn past(&self) -> &'static str {
        match self {
            Operation::Install(_) => "Installed",
            Operation::Remove(_) => "Removed",
            Operation::Upgrade(_) | Operation::UpgradeAll => "Upgraded",
            Operation::UpdateIndex => "Updated",
        }
    }

    /// What the operation acts on, e.g. a package name.
    pub fn subject(&self) -> String {
        match self {
            Operation::Install(name) | Operation::Remove(name) | Operation::Upgrade(name) => {
                name.clone()
            }
            Operation::UpgradeAll => "all packages".into(),
            Operation::UpdateIndex => "package indexes".into(),
        }
    }
}

/// Short apk-tools version string, e.g. `apk-tools 3.0.8-r0`.
pub fn apk_version(runner: &dyn Runner) -> Result<String> {
    let out = runner.capture(&["apk".to_string(), "--version".to_string()])?;
    let first = out.lines().next().unwrap_or_default();
    Ok(first
        .split(',')
        .next()
        .unwrap_or_default()
        .trim()
        .to_string())
}

fn query(runner: &dyn Runner, filter: Option<&str>) -> Result<Vec<catalog::QueryRecord>> {
    let mut argv = vec!["apk", "query", "--format", "json", "--fields", QUERY_FIELDS];
    argv.extend(filter);
    argv.push("*");
    let argv: Vec<String> = argv.into_iter().map(String::from).collect();
    catalog::parse_records(&runner.capture(&argv)?)
}

/// Loads the full package catalog using `apk query`.
pub fn load_catalog(runner: &dyn Runner, world: &[String]) -> Result<Vec<Package>> {
    let available = query(runner, None)?;
    let installed = query(runner, Some("--installed"))?;
    let upgradable: HashSet<String> = query(runner, Some("--upgradable"))?
        .into_iter()
        .map(|r| r.name)
        .collect();
    Ok(catalog::merge(available, installed, &upgradable, world))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn v(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn detect_root() {
        assert_eq!(Privilege::detect(0, |_| true), Privilege::Root);
    }

    #[test]
    fn detect_prefers_doas() {
        assert_eq!(Privilege::detect(1000, |_| true), Privilege::Doas);
        assert_eq!(Privilege::detect(1000, |p| p == "sudo"), Privilege::Sudo);
        assert_eq!(Privilege::detect(1000, |_| false), Privilege::Unavailable);
    }

    #[test]
    fn wrap_commands() {
        let cmd = v(&["apk", "add", "curl"]);
        assert_eq!(Privilege::Root.wrap(cmd.clone(), false), cmd);
        assert_eq!(
            Privilege::Doas.wrap(cmd.clone(), false),
            v(&["doas", "-n", "apk", "add", "curl"])
        );
        assert_eq!(
            Privilege::Sudo.wrap(cmd.clone(), false),
            v(&["sudo", "-n", "apk", "add", "curl"])
        );
        assert_eq!(
            Privilege::Doas.wrap(cmd.clone(), true),
            v(&["doas", "apk", "add", "curl"])
        );
        assert_eq!(
            Privilege::Sudo.wrap(cmd.clone(), true),
            v(&["sudo", "apk", "add", "curl"])
        );
        assert_eq!(Privilege::Unavailable.wrap(cmd.clone(), false), cmd);
    }

    #[test]
    fn check_argv() {
        assert_eq!(Privilege::Root.check_argv(), None);
        assert_eq!(Privilege::Unavailable.check_argv(), None);
        assert_eq!(
            Privilege::Doas.check_argv(),
            Some(v(&["doas", "-n", "true"]))
        );
        assert_eq!(
            Privilege::Sudo.check_argv(),
            Some(v(&["sudo", "-n", "true"]))
        );
    }

    #[test]
    fn current_uid_matches_id_command() {
        let out = std::process::Command::new("id").arg("-u").output().unwrap();
        let expected: u32 = String::from_utf8_lossy(&out.stdout).trim().parse().unwrap();
        assert_eq!(current_uid(), expected);
    }

    #[test]
    fn has_program_searches_path() {
        assert!(has_program("sh"));
        assert!(!has_program("definitely-not-a-real-program-bapk"));
    }

    #[test]
    fn operation_argv() {
        assert_eq!(
            Operation::Install("curl".into()).argv(),
            v(&["apk", "--no-progress", "add", "curl"])
        );
        assert_eq!(
            Operation::Remove("curl".into()).argv(),
            v(&["apk", "--no-progress", "del", "curl"])
        );
        assert_eq!(
            Operation::Upgrade("curl".into()).argv(),
            v(&["apk", "--no-progress", "add", "--upgrade", "curl"])
        );
        assert_eq!(
            Operation::UpgradeAll.argv(),
            v(&["apk", "--no-progress", "upgrade"])
        );
        assert_eq!(
            Operation::UpdateIndex.argv(),
            v(&["apk", "--no-progress", "update"])
        );
    }

    #[test]
    fn operation_labels() {
        let i = Operation::Install("curl".into());
        assert_eq!(
            (i.verb(), i.past(), i.subject().as_str()),
            ("Installing", "Installed", "curl")
        );
        let r = Operation::Remove("curl".into());
        assert_eq!((r.verb(), r.past()), ("Removing", "Removed"));
        let u = Operation::Upgrade("curl".into());
        assert_eq!((u.verb(), u.past()), ("Upgrading", "Upgraded"));
        let a = Operation::UpgradeAll;
        assert_eq!(
            (a.verb(), a.past(), a.subject().as_str()),
            ("Upgrading", "Upgraded", "all packages")
        );
        let x = Operation::UpdateIndex;
        assert_eq!(
            (x.verb(), x.past(), x.subject().as_str()),
            ("Updating", "Updated", "package indexes")
        );
    }

    /// Fake runner returning canned output depending on the argv.
    struct FakeRunner {
        calls: Mutex<Vec<Vec<String>>>,
    }

    impl FakeRunner {
        fn new() -> Self {
            FakeRunner {
                calls: Mutex::new(Vec::new()),
            }
        }
    }

    impl Runner for FakeRunner {
        fn capture(&self, argv: &[String]) -> Result<String> {
            self.calls.lock().unwrap().push(argv.to_vec());
            let has = |flag: &str| argv.iter().any(|a| a == flag);
            Ok(if has("--version") {
                "apk-tools 3.0.8-r0, compiled for aarch64.\n".into()
            } else if has("--installed") {
                r#"[{"name":"curl","version":"8.0-r0","repositories":["lib/apk/db/installed"]},
                    {"name":"local","version":"1-r0","repositories":["lib/apk/db/installed"]}]"#
                    .into()
            } else if has("--upgradable") {
                r#"[{"name":"curl","version":"8.1-r0"}]"#.into()
            } else {
                r#"[{"name":"curl","version":"8.1-r0","repositories":["https://m/alpine/v3.24/main"]},
                    {"name":"zsh","version":"5.9-r7","repositories":["https://m/alpine/v3.24/main"]}]"#
                    .into()
            })
        }
    }

    #[test]
    fn apk_version_strips_compile_info() {
        assert_eq!(
            apk_version(&FakeRunner::new()).unwrap(),
            "apk-tools 3.0.8-r0"
        );
    }

    #[test]
    fn load_catalog_merges_queries() {
        let runner = FakeRunner::new();
        let pkgs = load_catalog(&runner, &["curl".to_string()]).unwrap();
        let names: Vec<&str> = pkgs.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, vec!["curl", "local", "zsh"]);
        let curl = &pkgs[0];
        assert!(curl.installed && curl.upgradable && curl.explicit);
        assert_eq!(curl.installed_version.as_deref(), Some("8.0-r0"));
        assert!(!pkgs[2].installed);
    }

    #[test]
    fn load_catalog_uses_json_queries() {
        let runner = FakeRunner::new();
        load_catalog(&runner, &[]).unwrap();
        let calls = runner.calls.lock().unwrap();
        assert_eq!(calls.len(), 3);
        for call in calls.iter() {
            assert_eq!(&call[..2], &["apk".to_string(), "query".to_string()]);
            assert!(call.windows(2).any(|w| w == ["--format", "json"]));
            assert!(
                call.windows(2)
                    .any(|w| w[0] == "--fields" && w[1] == QUERY_FIELDS)
            );
            assert_eq!(call.last().unwrap(), "*");
        }
    }
}
