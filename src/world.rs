//! Parsing of the apk world file (`/etc/apk/world`).
//!
//! The format follows apk-world(5): whitespace separated dependency atoms such as
//! `curl`, `bash>=5`, `foo@testing` or `!conflict`. Lines may contain `#` comments.

/// Extracts package names from world-file content, preserving order and dropping duplicates.
pub fn parse_world(content: &str) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    for line in content.lines() {
        let line = line.split('#').next().unwrap_or_default();
        for atom in line.split_whitespace().filter(|a| !a.starts_with('!')) {
            let end = atom.find(['<', '>', '=', '~', '@']).unwrap_or(atom.len());
            let name = &atom[..end];
            if !name.is_empty() && !names.iter().any(|n| n == name) {
                names.push(name.to_string());
            }
        }
    }
    names
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_one_name_per_line() {
        assert_eq!(parse_world("curl\nbash\n"), vec!["curl", "bash"]);
    }

    #[test]
    fn parses_whitespace_separated_names() {
        assert_eq!(parse_world("curl  bash\tgit"), vec!["curl", "bash", "git"]);
    }

    #[test]
    fn ignores_comments_and_blank_lines() {
        let text = "# dev tools\n\ncurl # http client\n   # indented comment\ngit\n";
        assert_eq!(parse_world(text), vec!["curl", "git"]);
    }

    #[test]
    fn strips_version_constraints_and_tags() {
        let text = "bash>=5.0 foo=1.2-r0 bar<2 baz~1.1 qux@testing zed><1.0 a>1";
        assert_eq!(
            parse_world(text),
            vec!["bash", "foo", "bar", "baz", "qux", "zed", "a"]
        );
    }

    #[test]
    fn skips_conflicts() {
        assert_eq!(parse_world("!busybox-suid curl"), vec!["curl"]);
    }

    #[test]
    fn removes_duplicates_preserving_order() {
        assert_eq!(
            parse_world("git curl git bash curl"),
            vec!["git", "curl", "bash"]
        );
    }
}
