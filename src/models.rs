//! Core domain types for bapk.

/// The repository a package comes from.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Repo {
    Main,
    Community,
    Testing,
    Other(String),
    /// Installed but not available from any configured repository.
    #[default]
    Local,
}

impl Repo {
    /// Derives the repository from the `repositories` list returned by `apk query`.
    pub fn from_repositories(repos: &[String]) -> Repo {
        let Some(url) = repos.iter().find(|r| !r.ends_with("lib/apk/db/installed")) else {
            return Repo::Local;
        };
        let segment = url.trim_end_matches('/').rsplit('/').next().unwrap_or_default();
        match segment {
            "main" => Repo::Main,
            "community" => Repo::Community,
            "testing" => Repo::Testing,
            other => Repo::Other(other.to_string()),
        }
    }

    /// Short tag shown in the table's type column.
    pub fn tag(&self) -> &'static str {
        match self {
            Repo::Main => "[M]",
            Repo::Community => "[C]",
            Repo::Testing => "[T]",
            Repo::Other(_) => "[O]",
            Repo::Local => "[L]",
        }
    }

    /// Human readable repository label.
    pub fn label(&self) -> String {
        match self {
            Repo::Main => "main".into(),
            Repo::Community => "community".into(),
            Repo::Testing => "testing".into(),
            Repo::Other(name) => name.clone(),
            Repo::Local => "local (not in any repository)".into(),
        }
    }
}

/// A unified view of an apk package for display.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Package {
    pub name: String,
    /// Latest available version (or installed version for local packages).
    pub version: String,
    pub description: String,
    pub url: String,
    pub license: String,
    pub origin: String,
    pub maintainer: String,
    pub repo: Repo,
    pub file_size: u64,
    pub installed_size: u64,
    pub depends: Vec<String>,
    pub installed: bool,
    pub installed_version: Option<String>,
    pub upgradable: bool,
    /// Explicitly requested in /etc/apk/world.
    pub explicit: bool,
}

/// How the package list is sorted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SortMode {
    #[default]
    None,
    Size,
    Name,
}

impl SortMode {
    pub fn next(self) -> SortMode {
        match self {
            SortMode::None => SortMode::Size,
            SortMode::Size => SortMode::Name,
            SortMode::Name => SortMode::None,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            SortMode::None => "None",
            SortMode::Size => "Size",
            SortMode::Name => "Name",
        }
    }
}

/// Active package filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Filter {
    #[default]
    None,
    Installed,
    Upgradable,
    World,
    Main,
    Community,
}

impl Filter {
    pub fn matches(self, pkg: &Package) -> bool {
        match self {
            Filter::None => true,
            Filter::Installed => pkg.installed,
            Filter::Upgradable => pkg.installed && pkg.upgradable,
            Filter::World => pkg.installed && pkg.explicit,
            Filter::Main => pkg.repo == Repo::Main,
            Filter::Community => pkg.repo == Repo::Community,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Filter::None => "All",
            Filter::Installed => "Installed",
            Filter::Upgradable => "Upgradable",
            Filter::World => "World",
            Filter::Main => "Main",
            Filter::Community => "Community",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repos(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn repo_from_main_url() {
        let r = Repo::from_repositories(&repos(&["https://dl-cdn.alpinelinux.org/alpine/v3.24/main"]));
        assert_eq!(r, Repo::Main);
    }

    #[test]
    fn repo_from_community_url_with_trailing_slash() {
        let r = Repo::from_repositories(&repos(&["https://mirror/alpine/edge/community/"]));
        assert_eq!(r, Repo::Community);
    }

    #[test]
    fn repo_from_testing_url() {
        let r = Repo::from_repositories(&repos(&["https://mirror/alpine/edge/testing"]));
        assert_eq!(r, Repo::Testing);
    }

    #[test]
    fn repo_skips_installed_database() {
        let r = Repo::from_repositories(&repos(&[
            "lib/apk/db/installed",
            "https://mirror/alpine/v3.24/community",
        ]));
        assert_eq!(r, Repo::Community);
    }

    #[test]
    fn repo_only_installed_database_is_local() {
        assert_eq!(Repo::from_repositories(&repos(&["lib/apk/db/installed"])), Repo::Local);
        assert_eq!(Repo::from_repositories(&[]), Repo::Local);
    }

    #[test]
    fn repo_unknown_is_other_with_last_segment() {
        let r = Repo::from_repositories(&repos(&["/home/me/packages/custom"]));
        assert_eq!(r, Repo::Other("custom".into()));
    }

    #[test]
    fn repo_tags_and_labels() {
        assert_eq!(Repo::Main.tag(), "[M]");
        assert_eq!(Repo::Community.tag(), "[C]");
        assert_eq!(Repo::Testing.tag(), "[T]");
        assert_eq!(Repo::Other("x".into()).tag(), "[O]");
        assert_eq!(Repo::Local.tag(), "[L]");
        assert_eq!(Repo::Main.label(), "main");
        assert_eq!(Repo::Other("custom".into()).label(), "custom");
        assert_eq!(Repo::Local.label(), "local (not in any repository)");
    }

    #[test]
    fn sort_mode_cycles() {
        assert_eq!(SortMode::None.next(), SortMode::Size);
        assert_eq!(SortMode::Size.next(), SortMode::Name);
        assert_eq!(SortMode::Name.next(), SortMode::None);
        assert_eq!(SortMode::Size.label(), "Size");
        assert_eq!(SortMode::None.label(), "None");
        assert_eq!(SortMode::Name.label(), "Name");
    }

    fn pkg() -> Package {
        Package { name: "x".into(), repo: Repo::Main, ..Default::default() }
    }

    #[test]
    fn filter_none_matches_everything() {
        assert!(Filter::None.matches(&pkg()));
    }

    #[test]
    fn filter_installed() {
        let mut p = pkg();
        assert!(!Filter::Installed.matches(&p));
        p.installed = true;
        assert!(Filter::Installed.matches(&p));
    }

    #[test]
    fn filter_upgradable_requires_installed() {
        let mut p = pkg();
        p.upgradable = true;
        assert!(!Filter::Upgradable.matches(&p));
        p.installed = true;
        assert!(Filter::Upgradable.matches(&p));
    }

    #[test]
    fn filter_world_requires_explicit_and_installed() {
        let mut p = pkg();
        p.explicit = true;
        assert!(!Filter::World.matches(&p));
        p.installed = true;
        assert!(Filter::World.matches(&p));
    }

    #[test]
    fn filter_by_repo() {
        let mut p = pkg();
        assert!(Filter::Main.matches(&p));
        assert!(!Filter::Community.matches(&p));
        p.repo = Repo::Community;
        assert!(Filter::Community.matches(&p));
    }

    #[test]
    fn filter_labels() {
        assert_eq!(Filter::None.label(), "All");
        assert_eq!(Filter::Installed.label(), "Installed");
        assert_eq!(Filter::Upgradable.label(), "Upgradable");
        assert_eq!(Filter::World.label(), "World");
        assert_eq!(Filter::Main.label(), "Main");
        assert_eq!(Filter::Community.label(), "Community");
    }
}
