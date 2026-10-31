//! Small text formatting helpers.

/// Formats a byte count using binary units, e.g. `1.4 MiB`.
pub fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["KiB", "MiB", "GiB", "TiB"];
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let mut value = bytes as f64 / 1024.0;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.1} {}", UNITS[unit])
}

/// Truncates to at most `max` characters, ending with `…` when shortened.
pub fn truncate(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    let mut out: String = text.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_in_bytes() {
        assert_eq!(human_size(0), "0 B");
        assert_eq!(human_size(1023), "1023 B");
    }

    #[test]
    fn sizes_in_larger_units() {
        assert_eq!(human_size(1024), "1.0 KiB");
        assert_eq!(human_size(630358), "615.6 KiB");
        assert_eq!(human_size(1480846), "1.4 MiB");
        assert_eq!(human_size(5 * 1024 * 1024 * 1024), "5.0 GiB");
    }

    #[test]
    fn truncate_short_text_unchanged() {
        assert_eq!(truncate("1.0-r0", 15), "1.0-r0");
        assert_eq!(truncate("exactly15chars!", 15), "exactly15chars!");
    }

    #[test]
    fn truncate_long_text_with_ellipsis() {
        assert_eq!(truncate("20250814.1_git2025-r10", 15), "20250814.1_git…");
    }

    #[test]
    fn truncate_counts_characters_not_bytes() {
        assert_eq!(truncate("ééééé", 3), "éé…");
    }
}
