//! Command-line interface.

use clap::Parser;

#[derive(Debug, Parser, PartialEq, Eq)]
#[command(
    name = "bapk",
    about = "Bold APK - A TUI for Alpine Linux apk package management",
    disable_version_flag = true
)]
pub struct Cli {
    /// Show version information
    #[arg(short = 'v', long = "version")]
    pub version: bool,
}

/// Text printed by `--version`.
pub fn version_string() -> String {
    format!("{} {}", crate::app::APP_NAME, env!("CARGO_PKG_VERSION"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_arguments() {
        let cli = Cli::try_parse_from(["bapk"]).unwrap();
        assert_eq!(cli, Cli { version: false });
    }

    #[test]
    fn world_file_flag_is_rejected() {
        assert!(Cli::try_parse_from(["bapk", "-f", "/tmp/world"]).is_err());
    }

    #[test]
    fn version_flags() {
        assert!(Cli::try_parse_from(["bapk", "-v"]).unwrap().version);
        assert!(Cli::try_parse_from(["bapk", "--version"]).unwrap().version);
    }

    #[test]
    fn unknown_flag_is_error() {
        assert!(Cli::try_parse_from(["bapk", "--nope"]).is_err());
    }

    #[test]
    fn version_text() {
        assert_eq!(
            version_string(),
            format!("Bold APK {}", env!("CARGO_PKG_VERSION"))
        );
    }
}
