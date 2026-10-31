//! Heuristic detection of packages that provide a terminal user interface.
//!
//! apk metadata has no "TUI" tag, and linking against ncurses is a poor signal (shells,
//! pagers and interpreters link it too, while Rust/Go TUIs link nothing). Instead a package
//! counts as a TUI when its name or description says so, or it is a well-known TUI whose
//! description doesn't. Subpackages (docs, completions, ...) and libraries are excluded.

/// Well-known TUI applications whose descriptions don't identify them as such.
const KNOWN: &[&str] = &[
    "abook", "aerc", "alpine", "alsamixer", "aptitude", "atop", "bmon", "bottom", "btop",
    "calcurse", "cbonsai", "ccmake", "cmatrix", "cmus", "dialog", "dvtm", "elinks", "emacs-nox",
    "gdu", "gitui", "glances", "gnu-games", "helix", "htop", "iftop", "iotop-c", "iptraf-ng",
    "irssi", "kakoune", "lnav", "lynx", "mc", "mcabber", "micro", "minicom", "mutt", "nano",
    "ncdu", "neomutt", "neovim", "nethack", "nethogs", "newsboat", "nmon", "nmtui", "nnn",
    "nvtop", "powertop", "ranger", "rtorrent", "sc", "screen", "slrn", "tig", "tin", "tmux",
    "vim", "vis", "w3m", "yazi", "zellij",
];

/// Phrases in a description that mark a TUI (matched case-insensitively on word boundaries).
const KEYWORDS: &[&str] = &[
    "tui",
    "terminal user interface",
    "text user interface",
    "terminal ui",
    "terminal interface",
    "terminal-based",
    "terminal based",
    "console-based",
    "console based",
    "curses",
    "ncurses",
    "full screen",
    "full-screen",
];

/// Name suffixes of subpackages that never contain the program itself.
const SUBPACKAGE_SUFFIXES: &[&str] = &[
    "-doc", "-dev", "-dbg", "-static", "-libs", "-lang", "-openrc", "-systemd", "-pyc",
    "-common", "-completion", "-bash-completion", "-zsh-completion", "-fish-completion",
    "-nu-completion", "-vim", "-lisp",
];

/// Name prefixes of language bindings and libraries.
const LIBRARY_PREFIXES: &[&str] = &["lib", "py3-", "perl-", "lua", "ocaml-", "ruby-", "php", "rust-", "go-"];

/// Returns true when the package looks like a terminal user interface application.
pub fn is_tui(name: &str, description: &str) -> bool {
    if SUBPACKAGE_SUFFIXES.iter().any(|s| name.ends_with(s))
        || LIBRARY_PREFIXES.iter().any(|p| name.starts_with(p))
    {
        return false;
    }
    if KNOWN.contains(&name) {
        return true;
    }
    let desc = description.to_lowercase();
    if ["library", "bindings", "replacement for"].iter().any(|w| desc.contains(w)) {
        return false;
    }
    name.split(['-', '_']).any(|part| part == "tui")
        || KEYWORDS.iter().any(|k| contains_phrase(&desc, k))
}

/// True when `phrase` occurs in `text` delimited by non-alphanumeric characters.
fn contains_phrase(text: &str, phrase: &str) -> bool {
    text.match_indices(phrase).any(|(i, m)| {
        let before = text[..i].chars().next_back();
        let after = text[i + m.len()..].chars().next();
        !before.is_some_and(char::is_alphanumeric) && !after.is_some_and(char::is_alphanumeric)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn description_keywords() {
        assert!(is_tui("k9s", "Kubernetes TUI"));
        assert!(is_tui("lazygit", "Simple terminal UI for git commands"));
        assert!(is_tui("gpg-tui", "Terminal user interface for GnuPG"));
        assert!(is_tui("cmus", "feature-rich ncurses-based music player"));
        assert!(is_tui("cfdisk", "Curses based partition table manipulator"));
        assert!(is_tui("micro", "Modern and intuitive terminal-based text editor"));
        assert!(is_tui("mtr", "Full screen ncurses traceroute tool"));
    }

    #[test]
    fn keywords_need_word_boundaries() {
        assert!(!is_tui("foo", "Intuitive tool"));
        assert!(!is_tui("bar", "Recurses into directories"));
    }

    #[test]
    fn tui_in_name() {
        assert!(is_tui("networkmanager-tui", "NetworkManager text interface"));
        assert!(is_tui("jj_tui", "Jujutsu client"));
        assert!(!is_tui("tuigreet", "Graphical console greeter"));
    }

    #[test]
    fn well_known_tuis() {
        assert!(is_tui("htop", "Interactive process viewer"));
        assert!(is_tui("tmux", "Tool to control multiple terminals from a single terminal"));
        assert!(is_tui("vim", "Improved vi-style text editor"));
    }

    #[test]
    fn non_tuis() {
        assert!(!is_tui("curl", "URL retrieval utility and library"));
        assert!(!is_tui("zsh", "Very advanced and programmable command interpreter (shell)"));
    }

    #[test]
    fn excludes_subpackages_and_libraries() {
        assert!(!is_tui("gpg-tui-bash-completion", "Bash completions for gpg-tui"));
        assert!(!is_tui("htop-doc", "Interactive process viewer (documentation)"));
        assert!(!is_tui("s-tui-pyc", "Precompiled Python bytecode for s-tui"));
        assert!(!is_tui("ocaml-curses", "OCaml bindings for ncurses"));
        assert!(!is_tui("notcurses", "blingful character graphics and TUI library"));
        assert!(!is_tui("editline", "readline() replacement for UNIX without termcap (ncurses)"));
        assert!(!is_tui("libgnt", "ncurses toolkit"));
    }
}
