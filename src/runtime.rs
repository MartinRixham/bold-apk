//! Side-effect execution for [`crate::app::Command`]s. Functions take their I/O as
//! parameters (executors, fetchers, directories) so they can be tested in isolation.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};

use crate::apk::{Operation, Privilege};
use crate::app::AppEvent;
use crate::models::Package;
use crate::secdb::{SecDb, Vulnerability};

/// How privileged operations are executed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecMode {
    /// Run the apk command as-is (already root, or no escalation tool available).
    Direct,
    /// Prefix with doas/sudo `-n` and stream output into the TUI.
    Streamed,
    /// Suspend the TUI and run in the terminal so a password can be entered.
    Interactive,
}

/// Chooses the execution mode. `can_escalate_silently` is the result of `Privilege::check_argv`.
pub fn plan_execution(privilege: Privilege, can_escalate_silently: bool) -> ExecMode {
    match privilege {
        Privilege::Root | Privilege::Unavailable => ExecMode::Direct,
        Privilege::Doas | Privilege::Sudo if can_escalate_silently => ExecMode::Streamed,
        Privilege::Doas | Privilege::Sudo => ExecMode::Interactive,
    }
}

/// Runs operations sequentially, streaming output through `send`.
/// `exec` runs one argv, calling the line callback for each output line.
pub fn run_operations<E, S>(operations: &[Operation], wrap: impl Fn(Vec<String>) -> Vec<String>, mut exec: E, mut send: S)
where
    E: FnMut(&[String], &mut dyn FnMut(String)) -> Result<()>,
    S: FnMut(AppEvent),
{
    let total = operations.len();
    let mut failed = 0;
    for (i, operation) in operations.iter().enumerate() {
        send(AppEvent::OperationStarted { index: i + 1, total, operation: operation.clone() });
        let argv = wrap(operation.argv());
        let result = exec(&argv, &mut |line| send(AppEvent::OutputLine(line)));
        let error = result.err().map(|e| e.to_string());
        failed += usize::from(error.is_some());
        send(AppEvent::OperationFinished { operation: operation.clone(), error });
    }
    send(AppEvent::BatchFinished { total, failed });
}

/// Command used to download a URL to stdout.
pub fn fetch_argv(url: &str) -> Vec<String> {
    ["wget", "-q", "-O", "-", url].map(String::from).to_vec()
}

/// Loads the security database for `branch`, using files in `cache_dir` younger than `max_age`.
pub fn load_secdb(
    branch: &str,
    cache_dir: &Path,
    max_age: Duration,
    fetch: impl Fn(&str) -> Result<String>,
) -> Result<SecDb> {
    let mut db = SecDb::default();
    for url in crate::secdb::urls_for_branch(branch) {
        let repo = url.rsplit('/').next().unwrap_or_default();
        let cache = cache_dir.join(format!("secdb-{branch}-{repo}"));
        let fresh = std::fs::metadata(&cache)
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.elapsed().ok())
            .is_some_and(|age| age < max_age);
        let json = if fresh {
            std::fs::read_to_string(&cache)?
        } else {
            match fetch(&url) {
                Ok(json) => {
                    // A failed cache write is not fatal; the data is still usable.
                    let _ = std::fs::create_dir_all(cache_dir).and_then(|_| std::fs::write(&cache, &json));
                    json
                }
                Err(err) => std::fs::read_to_string(&cache)
                    .map_err(|_| err)
                    .with_context(|| format!("failed to download {url}"))?,
            }
        };
        db.extend(SecDb::parse(&json).with_context(|| format!("invalid secdb data from {url}"))?);
    }
    Ok(db)
}

/// Vulnerabilities affecting the installed (or else latest available) version of `pkg`.
pub fn scan_package(pkg: &Package, db: &SecDb) -> Vec<Vulnerability> {
    let origin = if pkg.origin.is_empty() { &pkg.name } else { &pkg.origin };
    let version = pkg.installed_version.as_deref().unwrap_or(&pkg.version);
    db.vulnerabilities(origin, version)
}

/// Directory for cached data: `$XDG_CACHE_HOME/bapk`, else `~/.cache/bapk`.
pub fn cache_dir(xdg_cache_home: Option<&str>, home: Option<&str>) -> PathBuf {
    match (xdg_cache_home.filter(|x| !x.is_empty()), home) {
        (Some(xdg), _) => Path::new(xdg).join("bapk"),
        (None, Some(home)) => Path::new(home).join(".cache/bapk"),
        (None, None) => PathBuf::from("/tmp/bapk"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    use anyhow::bail;

    #[test]
    fn plan_execution_modes() {
        assert_eq!(plan_execution(Privilege::Root, false), ExecMode::Direct);
        assert_eq!(plan_execution(Privilege::Unavailable, false), ExecMode::Direct);
        assert_eq!(plan_execution(Privilege::Doas, true), ExecMode::Streamed);
        assert_eq!(plan_execution(Privilege::Sudo, true), ExecMode::Streamed);
        assert_eq!(plan_execution(Privilege::Doas, false), ExecMode::Interactive);
        assert_eq!(plan_execution(Privilege::Sudo, false), ExecMode::Interactive);
    }

    fn wrap(argv: Vec<String>) -> Vec<String> {
        Privilege::Doas.wrap(argv, false)
    }

    #[test]
    fn run_operations_streams_events_in_order() {
        let ops = vec![Operation::Install("a".into()), Operation::Install("b".into())];
        let mut events = Vec::new();
        let mut argvs = Vec::new();
        run_operations(
            &ops,
            wrap,
            |argv, on_line| {
                argvs.push(argv.to_vec());
                on_line(format!("output for {}", argv.last().unwrap()));
                Ok(())
            },
            |e| events.push(e),
        );
        assert_eq!(argvs[0], vec!["doas", "-n", "apk", "--no-progress", "add", "a"]);
        assert_eq!(argvs.len(), 2);
        assert_eq!(
            events,
            vec![
                AppEvent::OperationStarted { index: 1, total: 2, operation: ops[0].clone() },
                AppEvent::OutputLine("output for a".into()),
                AppEvent::OperationFinished { operation: ops[0].clone(), error: None },
                AppEvent::OperationStarted { index: 2, total: 2, operation: ops[1].clone() },
                AppEvent::OutputLine("output for b".into()),
                AppEvent::OperationFinished { operation: ops[1].clone(), error: None },
                AppEvent::BatchFinished { total: 2, failed: 0 },
            ]
        );
    }

    #[test]
    fn run_operations_continues_after_failure() {
        let ops = vec![Operation::Remove("a".into()), Operation::Remove("b".into())];
        let mut events = Vec::new();
        run_operations(
            &ops,
            |a| a,
            |argv, _| if argv.last().unwrap() == "a" { bail!("permission denied") } else { Ok(()) },
            |e| events.push(e),
        );
        assert!(events.contains(&AppEvent::OperationFinished {
            operation: ops[0].clone(),
            error: Some("permission denied".into())
        }));
        assert!(events.contains(&AppEvent::OperationFinished { operation: ops[1].clone(), error: None }));
        assert_eq!(events.last(), Some(&AppEvent::BatchFinished { total: 2, failed: 1 }));
    }

    #[test]
    fn fetch_uses_wget() {
        assert_eq!(fetch_argv("https://x/y"), vec!["wget", "-q", "-O", "-", "https://x/y"]);
    }

    const MAIN: &str = r#"{"packages":[{"pkg":{"name":"openssl","secfixes":{"3.5.4-r0":["CVE-1"]}}}]}"#;
    const COMMUNITY: &str = r#"{"packages":[{"pkg":{"name":"7zip","secfixes":{"26.01-r0":["CVE-2"]}}}]}"#;

    fn fake_fetch(calls: &RefCell<Vec<String>>) -> impl Fn(&str) -> Result<String> + '_ {
        move |url: &str| {
            calls.borrow_mut().push(url.to_string());
            Ok(if url.ends_with("main.json") { MAIN } else { COMMUNITY }.to_string())
        }
    }

    #[test]
    fn load_secdb_fetches_and_caches() {
        let dir = tempfile::tempdir().unwrap();
        let calls = RefCell::new(Vec::new());
        let db = load_secdb("v3.24", dir.path(), Duration::from_secs(3600), fake_fetch(&calls)).unwrap();
        assert_eq!(calls.borrow().len(), 2);
        assert_eq!(db.vulnerabilities("openssl", "3.0-r0").len(), 1);
        assert_eq!(db.vulnerabilities("7zip", "1-r0").len(), 1);
        assert!(dir.path().join("secdb-v3.24-main.json").exists());

        let db = load_secdb("v3.24", dir.path(), Duration::from_secs(3600), fake_fetch(&calls)).unwrap();
        assert_eq!(calls.borrow().len(), 2, "second load should use cache");
        assert_eq!(db.vulnerabilities("openssl", "3.0-r0").len(), 1);
    }

    #[test]
    fn load_secdb_refetches_stale_cache() {
        let dir = tempfile::tempdir().unwrap();
        let calls = RefCell::new(Vec::new());
        load_secdb("v3.24", dir.path(), Duration::ZERO, fake_fetch(&calls)).unwrap();
        load_secdb("v3.24", dir.path(), Duration::ZERO, fake_fetch(&calls)).unwrap();
        assert_eq!(calls.borrow().len(), 4);
    }

    #[test]
    fn load_secdb_falls_back_to_stale_cache_when_offline() {
        let dir = tempfile::tempdir().unwrap();
        let calls = RefCell::new(Vec::new());
        load_secdb("v3.24", dir.path(), Duration::ZERO, fake_fetch(&calls)).unwrap();
        let db = load_secdb("v3.24", dir.path(), Duration::ZERO, |_| bail!("offline")).unwrap();
        assert_eq!(db.vulnerabilities("openssl", "3.0-r0").len(), 1);
    }

    #[test]
    fn load_secdb_errors_when_offline_without_cache() {
        let dir = tempfile::tempdir().unwrap();
        assert!(load_secdb("v3.24", dir.path(), Duration::ZERO, |_| bail!("offline")).is_err());
    }

    #[test]
    fn scan_uses_origin_and_installed_version() {
        let db = SecDb::parse(MAIN).unwrap();
        let mut p = Package {
            name: "libssl3".into(),
            origin: "openssl".into(),
            version: "3.6.0-r0".into(),
            ..Default::default()
        };
        assert!(scan_package(&p, &db).is_empty(), "latest available version is fixed");
        p.installed = true;
        p.installed_version = Some("3.5.0-r0".into());
        assert_eq!(scan_package(&p, &db).len(), 1, "installed version is vulnerable");
    }

    #[test]
    fn scan_falls_back_to_name_without_origin() {
        let db = SecDb::parse(MAIN).unwrap();
        let p = Package { name: "openssl".into(), version: "3.0-r0".into(), ..Default::default() };
        assert_eq!(scan_package(&p, &db).len(), 1);
    }

    #[test]
    fn cache_dir_prefers_xdg() {
        assert_eq!(cache_dir(Some("/x/cache"), Some("/home/u")), PathBuf::from("/x/cache/bapk"));
        assert_eq!(cache_dir(Some(""), Some("/home/u")), PathBuf::from("/home/u/.cache/bapk"));
        assert_eq!(cache_dir(None, Some("/home/u")), PathBuf::from("/home/u/.cache/bapk"));
        assert_eq!(cache_dir(None, None), PathBuf::from("/tmp/bapk"));
    }
}
