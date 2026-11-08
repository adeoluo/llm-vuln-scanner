//! Hashed n-gram counts for the refusal classifier; mirrors
//! `llm_vuln_scanner.detectors.refusal.ngram_counts_py` (input already normalized).

use regex::Regex;
use std::collections::HashMap;
use std::sync::OnceLock;

pub const OPENING_WORDS: usize = 6;
static WORD: OnceLock<Regex> = OnceLock::new();

/// 32-bit FNV-1a over the bytes of `prefix` followed by `data`.
pub fn fnv1a(prefix: u8, data: &[u8]) -> u32 {
    let mut h: u32 = 0x811C_9DC5;
    for &b in std::iter::once(&prefix).chain(data) {
        h ^= b as u32;
        h = h.wrapping_mul(0x0100_0193);
    }
    h
}

/// Sorted `(bucket, count)` pairs of the hashed n-grams of normalized text `t`.
pub fn ngram_counts(t: &str, dim_bits: u32) -> (Vec<u32>, Vec<u32>) {
    let mask: u32 = if dim_bits >= 32 {
        u32::MAX
    } else {
        (1u32 << dim_bits) - 1
    };
    let mut counts: HashMap<u32, u32> = HashMap::new();
    let padded = format!(" {t} ");
    let starts: Vec<usize> = padded
        .char_indices()
        .map(|(i, _)| i)
        .chain([padded.len()])
        .collect();
    let nchars = starts.len() - 1;
    for n in 3..=5usize {
        if nchars < n {
            continue;
        }
        for i in 0..=nchars - n {
            let g = &padded.as_bytes()[starts[i]..starts[i + n]];
            *counts.entry(fnv1a(b'c', g) & mask).or_insert(0) += 1;
        }
    }
    let word = WORD.get_or_init(|| Regex::new(r"[a-z0-9']+").expect("valid regex"));
    let words: Vec<&str> = word.find_iter(t).map(|m| m.as_str()).collect();
    for (i, w) in words.iter().enumerate() {
        *counts.entry(fnv1a(b'w', w.as_bytes()) & mask).or_insert(0) += 1;
        if i + 1 < words.len() {
            let bi = format!("{w} {}", words[i + 1]);
            *counts.entry(fnv1a(b'w', bi.as_bytes()) & mask).or_insert(0) += 1;
        }
    }
    let head = &words[..words.len().min(OPENING_WORDS)];
    for n in 1..=3usize {
        if head.len() < n {
            continue;
        }
        for i in 0..=head.len() - n {
            let g = head[i..i + n].join(" ");
            *counts.entry(fnv1a(b's', g.as_bytes()) & mask).or_insert(0) += 1;
        }
    }
    let mut pairs: Vec<(u32, u32)> = counts.into_iter().collect();
    pairs.sort_unstable();
    pairs.into_iter().unzip()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fnv_reference_values() {
        // FNV-1a test vectors: "" -> 0x811c9dc5, "a" -> 0xe40c292c.
        let mut h: u32 = 0x811C_9DC5;
        assert_eq!(h, 0x811c9dc5);
        h ^= b'a' as u32;
        h = h.wrapping_mul(0x0100_0193);
        assert_eq!(h, 0xe40c292c);
        assert_eq!(fnv1a(b'a', b""), 0xe40c292c);
    }

    #[test]
    fn counts_are_sorted_and_bounded() {
        let (idx, cnt) = ngram_counts("i am sorry, but i cannot help", 10);
        assert!(idx.windows(2).all(|w| w[0] < w[1]));
        assert!(idx.iter().all(|&i| i < 1024));
        assert!(cnt.iter().sum::<u32>() > 30);
        let (idx, _) = ngram_counts("", 18);
        assert!(idx.is_empty());
    }
}
