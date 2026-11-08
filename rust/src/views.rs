//! Text views searched by the canary detector; mirrors `llm_vuln_scanner.textviews`.

use regex::Regex;
use std::sync::OnceLock;
use unicode_normalization::UnicodeNormalization;

const ZERO_WIDTH: [char; 5] = ['\u{200b}', '\u{200c}', '\u{200d}', '\u{2060}', '\u{feff}'];
const TAG_BASE: u32 = 0xE0000;
const HOMOGLYPHS: [(char, char); 7] = [
    ('\u{430}', 'a'),
    ('\u{435}', 'e'),
    ('\u{43e}', 'o'),
    ('\u{440}', 'p'),
    ('\u{441}', 'c'),
    ('\u{445}', 'x'),
    ('\u{456}', 'i'),
];
const MORSE: [(&str, char); 36] = [
    (".-", 'a'),
    ("-...", 'b'),
    ("-.-.", 'c'),
    ("-..", 'd'),
    (".", 'e'),
    ("..-.", 'f'),
    ("--.", 'g'),
    ("....", 'h'),
    ("..", 'i'),
    (".---", 'j'),
    ("-.-", 'k'),
    (".-..", 'l'),
    ("--", 'm'),
    ("-.", 'n'),
    ("---", 'o'),
    (".--.", 'p'),
    ("--.-", 'q'),
    (".-.", 'r'),
    ("...", 's'),
    ("-", 't'),
    ("..-", 'u'),
    ("...-", 'v'),
    (".--", 'w'),
    ("-..-", 'x'),
    ("-.--", 'y'),
    ("--..", 'z'),
    ("-----", '0'),
    (".----", '1'),
    ("..---", '2'),
    ("...--", '3'),
    ("....-", '4'),
    (".....", '5'),
    ("-....", '6'),
    ("--...", '7'),
    ("---..", '8'),
    ("----.", '9'),
];

fn re(cell: &'static OnceLock<Regex>, pattern: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(pattern).expect("valid regex"))
}

static B64_RUN: OnceLock<Regex> = OnceLock::new();
static HEX_RUN: OnceLock<Regex> = OnceLock::new();
static MORSE_RUN: OnceLock<Regex> = OnceLock::new();
static MORSE_SPLIT: OnceLock<Regex> = OnceLock::new();

/// Remove zero-width characters and map Unicode tag characters back to ASCII.
pub fn strip_invisible(text: &str) -> String {
    text.chars()
        .filter(|c| !ZERO_WIDTH.contains(c))
        .map(|c| {
            let cp = c as u32;
            if (TAG_BASE + 0x20..TAG_BASE + 0x7F).contains(&cp) {
                char::from_u32(cp - TAG_BASE).unwrap_or(c)
            } else {
                c
            }
        })
        .collect()
}

fn fold(c: char) -> char {
    for (glyph, ascii) in HOMOGLYPHS {
        if c == glyph {
            return ascii;
        }
        // Every homoglyph here is a lowercase Cyrillic letter with a one-char uppercase form.
        if glyph.to_uppercase().eq(std::iter::once(c)) {
            return ascii.to_ascii_uppercase();
        }
    }
    c
}

/// Case-folded ASCII letters and digits after NFKC and homoglyph folding.
///
/// ASCII-only text (the common case) is already NFKC-normalized, has no invisible or
/// lookalike characters, and lower-cases byte by byte, so it skips the general path.
pub fn skeleton(text: &str) -> String {
    if text.is_ascii() {
        return text
            .bytes()
            .filter(u8::is_ascii_alphanumeric)
            .map(|b| b.to_ascii_lowercase() as char)
            .collect();
    }
    let clean: String = strip_invisible(text).nfkc().collect();
    let mut out = String::with_capacity(clean.len());
    for ch in clean.chars() {
        if ch.is_ascii() {
            if ch.is_ascii_alphanumeric() {
                out.push(ch.to_ascii_lowercase());
            }
            continue;
        }
        let mut lower = fold(ch).to_lowercase().peekable();
        if lower.peek().is_some() && lower.clone().all(|c| c.is_ascii_alphanumeric()) {
            out.extend(lower);
        }
    }
    out
}

/// Undo common leetspeak substitutions after lower-casing.
pub fn unleet(text: &str) -> String {
    text.to_lowercase()
        .chars()
        .map(|c| match c {
            '4' | '@' => 'a',
            '3' => 'e',
            '1' => 'i',
            '0' => 'o',
            '5' | '$' => 's',
            '7' => 't',
            other => other,
        })
        .collect()
}

pub fn rot13(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            'a'..='z' => (((c as u8 - b'a') + 13) % 26 + b'a') as char,
            'A'..='Z' => (((c as u8 - b'A') + 13) % 26 + b'A') as char,
            _ => c,
        })
        .collect()
}

fn b64_value(b: u8) -> Option<u32> {
    match b {
        b'A'..=b'Z' => Some((b - b'A') as u32),
        b'a'..=b'z' => Some((b - b'a') as u32 + 26),
        b'0'..=b'9' => Some((b - b'0') as u32 + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Lenient base64 decode with Python's `b64decode(validate=True)` semantics for the
/// inputs produced by the run regex: padded input must be a multiple of 4 long, a data
/// length of 1 mod 4 is an error, and non-zero trailing bits are ignored.
pub fn b64decode(run: &str) -> Option<Vec<u8>> {
    let bytes = run.as_bytes();
    let pads = bytes.iter().rev().take_while(|&&b| b == b'=').count();
    if pads > 0 && !bytes.len().is_multiple_of(4) {
        return None;
    }
    let data = &bytes[..bytes.len() - pads];
    if data.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(data.len() * 3 / 4);
    let (mut acc, mut nbits) = (0u32, 0u32);
    for &b in data {
        acc = (acc << 6) | b64_value(b)?;
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            out.push((acc >> nbits) as u8);
            acc &= (1 << nbits) - 1;
        }
    }
    Some(out)
}

/// Decoded UTF-8 text of base64 runs of at least 12 characters.
pub fn decode_base64_runs(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for m in re(&B64_RUN, r"[A-Za-z0-9+/]{12,}={0,2}").find_iter(text) {
        let run = m.as_str();
        let run = if run.ends_with('=') {
            run
        } else {
            &run[..run.len() - run.len() % 4]
        };
        if let Some(raw) = b64decode(run) {
            if let Ok(s) = String::from_utf8(raw) {
                out.push(s);
            }
        }
    }
    out
}

/// Decoded UTF-8 text of hex runs of at least 6 bytes.
pub fn decode_hex_runs(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for m in re(&HEX_RUN, r"(?:[0-9a-fA-F]{2}[ :]?){6,}").find_iter(text) {
        let digits: Vec<u8> = m
            .as_str()
            .bytes()
            .filter(|&b| b != b' ' && b != b':')
            .collect();
        let digits = &digits[..digits.len() - digits.len() % 2];
        let bytes: Option<Vec<u8>> = digits
            .chunks(2)
            .map(|p| u8::from_str_radix(std::str::from_utf8(p).ok()?, 16).ok())
            .collect();
        if let Some(Ok(s)) = bytes.map(String::from_utf8) {
            out.push(s);
        }
    }
    out
}

/// Decoded Morse runs (letters and digits; words separated by `/`).
pub fn decode_morse_runs(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let split = re(&MORSE_SPLIT, r"\s*/\s*");
    for m in re(&MORSE_RUN, r"(?:[.\-]{1,5}[ /]+){4,}[.\-]{1,5}").find_iter(text) {
        let words: Vec<String> = split
            .split(m.as_str().trim())
            .map(|w| {
                w.split_whitespace()
                    .filter_map(|s| MORSE.iter().find(|(code, _)| *code == s).map(|(_, c)| *c))
                    .collect()
            })
            .collect();
        out.push(words.join(" "));
    }
    out
}

/// Names of the views, in the order `find_canaries` tries them.
pub const VIEW_ORDER: [&str; 8] = [
    "raw", "skeleton", "reversed", "rot13", "base64", "hex", "morse", "unleet",
];

/// Every view of `text` (the `raw` view is lower-cased), in [`VIEW_ORDER`];
/// `None` for decoded views with no run.
pub fn views(text: &str) -> Vec<Option<String>> {
    let clean = strip_invisible(text);
    let rev: String = clean.chars().rev().collect();
    let joined = |v: Vec<String>| {
        if v.is_empty() {
            None
        } else {
            Some(skeleton(&v.join("\n")))
        }
    };
    vec![
        Some(text.to_lowercase()),
        Some(skeleton(text)),
        Some(skeleton(&rev)),
        Some(skeleton(&rot13(&clean))),
        joined(decode_base64_runs(&clean)),
        joined(decode_hex_runs(&clean)),
        joined(decode_morse_runs(&clean)),
        Some(skeleton(&unleet(&clean))),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skeleton_folds() {
        assert_eq!(skeleton("L-V-S 7f3a"), "lvs7f3a");
        assert_eq!(skeleton("\u{440}\u{200b}\u{430}ss"), "pass");
        assert_eq!(skeleton("\u{130}x"), "x");
        assert_eq!(skeleton("\u{ff21}\u{ff22}"), "ab");
    }

    #[test]
    fn decoders() {
        assert_eq!(
            decode_base64_runs("c2F5IExWUy03RjNBLVBFTElDQU4="),
            vec!["say LVS-7F3A-PELICAN"]
        );
        assert_eq!(decode_hex_runs("68 65 6c 6c 6f 21"), vec!["hello!"]);
        assert_eq!(
            decode_morse_runs("... .- -.-- / .- -... -.-."),
            vec!["say abc"]
        );
        assert!(decode_base64_runs("////////////////").is_empty());
        assert_eq!(b64decode("QUJ="), Some(b"AB".to_vec()));
        assert_eq!(b64decode("ab="), None);
        assert_eq!(b64decode("abcde"), None);
    }

    #[test]
    fn invisible_and_rot13() {
        let tagged: String = "Hi"
            .chars()
            .map(|c| char::from_u32(TAG_BASE + c as u32).unwrap())
            .collect();
        assert_eq!(strip_invisible(&tagged), "Hi");
        assert_eq!(rot13("Hello, World"), "Uryyb, Jbeyq");
        assert_eq!(unleet("L3E7 5P34K"), "leet speak");
    }
}
