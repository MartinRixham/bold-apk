//! Running external commands, either capturing output or streaming it line by line.

use std::io::{BufRead, BufReader, Read};
use std::process::{Command, Stdio};
use std::sync::mpsc;

use anyhow::{Context, Result, bail};

fn command(argv: &[String]) -> Result<Command> {
    let (program, args) = argv.split_first().context("empty command")?;
    let mut cmd = Command::new(program);
    cmd.args(args).stdin(Stdio::null());
    Ok(cmd)
}

fn spawn_reader<R: Read + Send + 'static>(reader: R, tx: mpsc::Sender<String>) {
    std::thread::spawn(move || {
        for line in BufReader::new(reader).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
}

/// Runs a command to completion and returns its stdout.
/// Fails with stderr included in the message if the command exits non-zero.
pub fn capture(argv: &[String]) -> Result<String> {
    let output = command(argv)?
        .output()
        .with_context(|| format!("failed to run {}", argv[0]))?;
    if !output.status.success() {
        bail!(
            "{} exited with {}: {}",
            argv.join(" "),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Runs a command with stdin closed, invoking `on_line` for every stdout/stderr line
/// as it is produced. Returns an error if the command fails to start or exits non-zero.
pub fn stream<F: FnMut(String)>(argv: &[String], mut on_line: F) -> Result<()> {
    let mut child = command(argv)?
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to run {}", argv[0]))?;
    let (tx, rx) = mpsc::channel();
    spawn_reader(child.stdout.take().context("missing stdout")?, tx.clone());
    spawn_reader(child.stderr.take().context("missing stderr")?, tx);
    for line in rx {
        on_line(line);
    }
    let status = child.wait()?;
    if !status.success() {
        bail!("{} exited with {}", argv.join(" "), status);
    }
    Ok(())
}

/// Abstraction over command capture so higher layers can be tested with fakes.
pub trait Runner: Send + Sync {
    fn capture(&self, argv: &[String]) -> Result<String>;
}

/// The real system runner.
pub struct SystemRunner;

impl Runner for SystemRunner {
    fn capture(&self, argv: &[String]) -> Result<String> {
        capture(argv)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sh(script: &str) -> Vec<String> {
        vec!["sh".into(), "-c".into(), script.into()]
    }

    #[test]
    fn capture_returns_stdout() {
        assert_eq!(capture(&sh("echo hello")).unwrap(), "hello\n");
    }

    #[test]
    fn capture_fails_on_nonzero_exit_with_stderr() {
        let err = capture(&sh("echo boom >&2; exit 2"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("boom"), "{err}");
    }

    #[test]
    fn capture_fails_for_missing_program() {
        assert!(capture(&["definitely-not-a-real-program-bapk".to_string()]).is_err());
    }

    #[test]
    fn capture_rejects_empty_argv() {
        assert!(capture(&[]).is_err());
    }

    #[test]
    fn stream_delivers_stdout_and_stderr_lines() {
        let mut lines = Vec::new();
        stream(&sh("echo one; echo two >&2; echo three"), |l| lines.push(l)).unwrap();
        lines.sort();
        assert_eq!(lines, vec!["one", "three", "two"]);
    }

    #[test]
    fn stream_preserves_stdout_order() {
        let mut lines = Vec::new();
        stream(&sh("for i in 1 2 3 4 5; do echo $i; done"), |l| {
            lines.push(l)
        })
        .unwrap();
        assert_eq!(lines, vec!["1", "2", "3", "4", "5"]);
    }

    #[test]
    fn stream_reports_failure_exit() {
        let mut lines = Vec::new();
        let res = stream(&sh("echo partial; exit 1"), |l| lines.push(l));
        assert!(res.is_err());
        assert_eq!(lines, vec!["partial"]);
    }

    #[test]
    fn stream_closes_stdin() {
        // `cat` would hang forever if stdin were inherited from the terminal.
        stream(&sh("cat"), |_| {}).unwrap();
    }
}
