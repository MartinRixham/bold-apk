//! Content of the package details panel.

use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};

use super::format::human_size;
use crate::models::Package;
use crate::secdb::Vulnerability;

const SEPARATOR: &str = "────────────────────────";

fn title(text: impl Into<String>, color: Color) -> Vec<Line<'static>> {
    vec![
        Line::from(Span::styled(text.into(), Style::new().fg(color).add_modifier(Modifier::BOLD))),
        Line::from(Span::styled(SEPARATOR, Style::new().add_modifier(Modifier::DIM))),
    ]
}

fn field(label: &str, value: impl Into<String>) -> Line<'static> {
    field_styled(label, Span::raw(value.into()))
}

fn field_styled(label: &str, value: Span<'static>) -> Line<'static> {
    Line::from(vec![Span::styled(format!("• {label}: "), Style::new().fg(Color::Blue)), value])
}

fn status(pkg: &Package) -> Span<'static> {
    match (pkg.installed, pkg.upgradable) {
        (false, _) => Span::styled("Not installed", Style::new().fg(Color::Red)),
        (true, true) => Span::styled("Update available", Style::new().fg(Color::LightRed)),
        (true, false) => Span::styled("Installed", Style::new().fg(Color::Green)),
    }
}

fn basic(pkg: &Package) -> Vec<Line<'static>> {
    let mut lines = title(pkg.name.clone(), Color::Yellow);
    lines.extend([
        field("Type", format!("{} {}", pkg.repo.tag(), pkg.repo.label())),
        field("Version", pkg.version.clone()),
        field_styled("Status", status(pkg)),
        field("Homepage", pkg.url.clone()),
        field("License", pkg.license.clone()),
        field("Origin", pkg.origin.clone()),
        field("Maintainer", pkg.maintainer.clone()),
        Line::default(),
    ]);
    lines.extend(title("Description", Color::Yellow));
    lines.push(Line::from(pkg.description.clone()));
    lines
}

fn security(vulns: &[Vulnerability]) -> Vec<Line<'static>> {
    if vulns.is_empty() {
        let mut lines = title("Security", Color::Yellow);
        lines.push(Line::from(Span::styled("✓ No known vulnerabilities", Style::new().fg(Color::Green))));
        return lines;
    }
    let noun = if vulns.len() == 1 { "vulnerability" } else { "vulnerabilities" };
    let mut lines = title(format!("⚠ Security ({} {noun})", vulns.len()), Color::Red);
    for v in vulns {
        lines.push(Line::from(vec![
            Span::styled(format!("  {}", v.id), Style::new().fg(Color::Red)),
            Span::styled(format!(" (fixed in {})", v.fixed_in), Style::new().add_modifier(Modifier::DIM)),
        ]));
    }
    lines
}

fn installation(pkg: &Package) -> Vec<Line<'static>> {
    let mut lines = title("Installation", Color::Yellow);
    if !pkg.installed {
        lines.push(Line::from("Not installed"));
        return lines;
    }
    lines.push(field("Installed version", pkg.installed_version.clone().unwrap_or_default()));
    lines.push(field("In world (explicit)", if pkg.explicit { "Yes" } else { "No" }));
    lines
}

fn dependencies(pkg: &Package) -> Vec<Line<'static>> {
    let mut lines = title("Dependencies", Color::Yellow);
    if pkg.depends.is_empty() {
        lines.push(Line::from("No dependencies"));
    }
    for chunk in pkg.depends.chunks(3) {
        lines.push(Line::from(chunk.join(", ")));
    }
    lines
}

fn sizes(pkg: &Package) -> Vec<Line<'static>> {
    let mut lines = title("Size", Color::Yellow);
    lines.push(field("Download size", human_size(pkg.file_size)));
    lines.push(field("Installed size", human_size(pkg.installed_size)));
    lines
}

/// Builds the details panel lines for a package. `vulns` is `None` when not scanned yet.
pub fn details_lines(pkg: Option<&Package>, vulns: Option<&Vec<Vulnerability>>) -> Vec<Line<'static>> {
    let Some(pkg) = pkg else {
        return Vec::new();
    };
    let mut sections = vec![basic(pkg)];
    if let Some(vulns) = vulns {
        sections.push(security(vulns));
    }
    sections.extend([installation(pkg), dependencies(pkg), sizes(pkg)]);
    let mut lines = Vec::new();
    for (i, section) in sections.into_iter().enumerate() {
        if i > 0 {
            lines.push(Line::default());
        }
        lines.extend(section);
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Repo;

    fn text(lines: &[Line]) -> String {
        lines
            .iter()
            .map(|l| l.spans.iter().map(|s| s.content.as_ref()).collect::<String>())
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn curl() -> Package {
        Package {
            name: "curl".into(),
            version: "8.1-r0".into(),
            description: "URL retrieval utility".into(),
            url: "https://curl.se/".into(),
            license: "curl".into(),
            origin: "curl".into(),
            maintainer: "Jane <jane@example.org>".into(),
            repo: Repo::Main,
            file_size: 630358,
            installed_size: 1480846,
            depends: vec!["ca-certificates".into(), "so:libc.musl-aarch64.so.1".into(), "libcurl".into(), "zlib".into()],
            ..Default::default()
        }
    }

    #[test]
    fn no_package_is_empty() {
        assert!(details_lines(None, None).is_empty());
    }

    #[test]
    fn basic_information() {
        let t = text(&details_lines(Some(&curl()), None));
        for expected in [
            "curl",
            "• Type: [M] main",
            "• Version: 8.1-r0",
            "• Status: Not installed",
            "• Homepage: https://curl.se/",
            "• License: curl",
            "• Origin: curl",
            "• Maintainer: Jane <jane@example.org>",
            "Description",
            "URL retrieval utility",
        ] {
            assert!(t.contains(expected), "missing {expected:?} in\n{t}");
        }
    }

    #[test]
    fn installation_status_variants() {
        let mut p = curl();
        let t = text(&details_lines(Some(&p), None));
        assert!(t.contains("Installation\n────────────────────────\nNot installed"), "{t}");
        p.installed = true;
        p.installed_version = Some("8.1-r0".into());
        p.explicit = true;
        let t = text(&details_lines(Some(&p), None));
        assert!(t.contains("• Status: Installed"), "{t}");
        assert!(t.contains("• Installed version: 8.1-r0"), "{t}");
        assert!(t.contains("• In world (explicit): Yes"), "{t}");
        p.upgradable = true;
        p.explicit = false;
        p.installed_version = Some("8.0-r0".into());
        let t = text(&details_lines(Some(&p), None));
        assert!(t.contains("• Status: Update available"), "{t}");
        assert!(t.contains("• In world (explicit): No"), "{t}");
    }

    #[test]
    fn dependencies_three_per_line() {
        let t = text(&details_lines(Some(&curl()), None));
        assert!(
            t.contains("Dependencies\n────────────────────────\nca-certificates, so:libc.musl-aarch64.so.1, libcurl\nzlib"),
            "{t}"
        );
    }

    #[test]
    fn no_dependencies() {
        let mut p = curl();
        p.depends.clear();
        assert!(text(&details_lines(Some(&p), None)).contains("No dependencies"));
    }

    #[test]
    fn sizes_section() {
        let t = text(&details_lines(Some(&curl()), None));
        assert!(t.contains("• Download size: 615.6 KiB"), "{t}");
        assert!(t.contains("• Installed size: 1.4 MiB"), "{t}");
    }

    #[test]
    fn security_section_only_when_scanned() {
        let t = text(&details_lines(Some(&curl()), None));
        assert!(!t.contains("Security"));
        let t = text(&details_lines(Some(&curl()), Some(&vec![])));
        assert!(t.contains("✓ No known vulnerabilities"), "{t}");
        let v = vec![
            Vulnerability { id: "CVE-2025-1".into(), fixed_in: "8.2-r0".into() },
            Vulnerability { id: "CVE-2025-2".into(), fixed_in: "8.3-r0".into() },
        ];
        let t = text(&details_lines(Some(&curl()), Some(&v)));
        assert!(t.contains("⚠ Security (2 vulnerabilities)"), "{t}");
        assert!(t.contains("CVE-2025-1 (fixed in 8.2-r0)"), "{t}");
        let t = text(&details_lines(Some(&curl()), Some(&v[..1].to_vec())));
        assert!(t.contains("⚠ Security (1 vulnerability)"), "{t}");
    }

    #[test]
    fn local_package_label() {
        let mut p = curl();
        p.repo = Repo::Local;
        let t = text(&details_lines(Some(&p), None));
        assert!(t.contains("• Type: [L] local (not in any repository)"), "{t}");
    }
}
