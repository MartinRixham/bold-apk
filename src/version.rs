//! Alpine apk version comparison.

use std::cmp::Ordering;

/// A single lexical component of an apk version string.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    /// Numeric component. `fraction` is set when a non-leading component starts
    /// with `0`, in which case apk compares it as a string.
    Digit { text: String, fraction: bool },
    Letter(char),
    /// `_suffix[N]`; rank < 0 means pre-release, > 0 post-release.
    Suffix { rank: i8, number: u64 },
    Revision(u64),
    End,
}

impl Token {
    fn type_rank(&self) -> u8 {
        match self {
            Token::Digit { .. } => 0,
            Token::Letter(_) => 1,
            Token::Suffix { .. } => 2,
            Token::Revision(_) => 3,
            Token::End => 4,
        }
    }
}

fn suffix_rank(name: &str) -> i8 {
    match name {
        "alpha" => -4,
        "beta" => -3,
        "pre" => -2,
        "rc" => -1,
        "cvs" => 1,
        "svn" => 2,
        "git" => 3,
        "hg" => 4,
        "p" => 5,
        _ => 0,
    }
}

fn take_while<F: Fn(char) -> bool>(chars: &[char], i: &mut usize, f: F) -> String {
    let start = *i;
    while *i < chars.len() && f(chars[*i]) {
        *i += 1;
    }
    chars[start..*i].iter().collect()
}

fn parse_number(text: &str) -> u64 {
    text.parse().unwrap_or(u64::MAX)
}

fn tokenize(version: &str) -> Vec<Token> {
    let chars: Vec<char> = version.chars().collect();
    let mut tokens = Vec::new();
    let mut i = 0;
    let mut first = true;
    while i < chars.len() {
        let c = chars[i];
        if c.is_ascii_digit() {
            let text = take_while(&chars, &mut i, |c| c.is_ascii_digit());
            let fraction = !first && text.starts_with('0') && text.len() > 1;
            tokens.push(Token::Digit { text, fraction });
            first = false;
        } else if c == '.' {
            i += 1;
        } else if c == '_' {
            i += 1;
            let name = take_while(&chars, &mut i, |c| c.is_ascii_lowercase());
            let num = take_while(&chars, &mut i, |c| c.is_ascii_digit());
            tokens.push(Token::Suffix {
                rank: suffix_rank(&name),
                number: if num.is_empty() { 0 } else { parse_number(&num) },
            });
        } else if c == '-' && chars.get(i + 1) == Some(&'r') {
            i += 2;
            let num = take_while(&chars, &mut i, |c| c.is_ascii_digit());
            tokens.push(Token::Revision(parse_number(&num)));
        } else if c.is_ascii_alphabetic() {
            tokens.push(Token::Letter(c));
            i += 1;
        } else {
            i += 1;
        }
    }
    tokens.push(Token::End);
    tokens
}

fn compare_digits(a: &str, a_frac: bool, b: &str, b_frac: bool) -> Ordering {
    if a_frac || b_frac {
        a.cmp(b)
    } else {
        let (a, b) = (a.trim_start_matches('0'), b.trim_start_matches('0'));
        a.len().cmp(&b.len()).then_with(|| a.cmp(b))
    }
}

/// Compares two apk version strings (e.g. `1.2.3_rc1-r0`).
pub fn compare(a: &str, b: &str) -> Ordering {
    let (ta, tb) = (tokenize(a), tokenize(b));
    for (x, y) in ta.iter().zip(tb.iter()) {
        let ord = match (x, y) {
            (Token::End, Token::End) => return Ordering::Equal,
            (
                Token::Digit { text: a, fraction: af },
                Token::Digit { text: b, fraction: bf },
            ) => compare_digits(a, *af, b, *bf),
            (Token::Letter(a), Token::Letter(b)) => a.cmp(b),
            (Token::Suffix { rank: ra, number: na }, Token::Suffix { rank: rb, number: nb }) => {
                ra.cmp(rb).then(na.cmp(nb))
            }
            (Token::Revision(a), Token::Revision(b)) => a.cmp(b),
            (Token::Suffix { rank, .. }, _) if *rank < 0 => Ordering::Less,
            (_, Token::Suffix { rank, .. }) if *rank < 0 => Ordering::Greater,
            // Different token kinds: the "more significant" kind wins.
            _ => y.type_rank().cmp(&x.type_rank()),
        };
        if ord != Ordering::Equal {
            return ord;
        }
    }
    Ordering::Equal
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp::Ordering::*;

    #[test]
    fn equal_versions() {
        assert_eq!(compare("1.0-r0", "1.0-r0"), Equal);
    }

    #[test]
    fn numeric_components_compare_numerically() {
        assert_eq!(compare("1.10", "1.9"), Greater);
        assert_eq!(compare("1.2.3", "1.2.10"), Less);
    }

    #[test]
    fn more_components_is_greater() {
        assert_eq!(compare("1.2.1", "1.2"), Greater);
    }

    #[test]
    fn revision_compares() {
        assert_eq!(compare("1.0-r1", "1.0-r0"), Greater);
        assert_eq!(compare("1.0-r10", "1.0-r9"), Greater);
        assert_eq!(compare("1.0", "1.0-r1"), Less);
    }

    #[test]
    fn letter_suffix_is_greater_than_none() {
        assert_eq!(compare("1.0a", "1.0"), Greater);
        assert_eq!(compare("1.0b", "1.0a"), Greater);
    }

    #[test]
    fn pre_release_suffixes_are_lower_than_release() {
        assert_eq!(compare("1.0_alpha1", "1.0"), Less);
        assert_eq!(compare("1.0_beta", "1.0_alpha"), Greater);
        assert_eq!(compare("1.0_pre1", "1.0_beta9"), Greater);
        assert_eq!(compare("1.0_rc1", "1.0_pre2"), Greater);
        assert_eq!(compare("1.0_rc2", "1.0_rc10"), Less);
    }

    #[test]
    fn post_release_suffixes_are_higher_than_release() {
        assert_eq!(compare("1.0_p1", "1.0"), Greater);
        assert_eq!(compare("1.0_git20240101", "1.0"), Greater);
        assert_eq!(compare("1.0_p1", "1.0_git1"), Greater);
    }

    #[test]
    fn real_world_versions() {
        assert_eq!(compare("3.32.1-r0", "3.32.2-r0"), Less);
        assert_eq!(compare("20250814.1-r0", "20240722.0-r3"), Greater);
        assert_eq!(compare("1.4.6-r0", "1.4.6-r0"), Equal);
    }

    #[test]
    fn leading_zero_after_dot_compares_as_fraction() {
        // apk treats ".05" < ".5" style components as fractional strings
        assert_eq!(compare("1.05", "1.5"), Less);
    }
}
