//! Bit-parallel longest common subsequence length.
//!
//! For sequences `a` (length m) and `b`, let `M[y]` be the bit vector of positions of
//! `a` holding symbol `y`. Starting from `V = 1...1` (m bits), each symbol `y` of `b`
//! updates `V <- (V + (V & M[y])) | (V & !M[y])` with carries across 64-bit words; the
//! LCS length is the number of zero bits of `V` (Allison and Dix, 1986; Hyyro, 2004).
//! The cost is O(ceil(m / 64) * n) word operations against O(m * n) for the dynamic
//! program.

use std::collections::HashMap;

/// LCS length of two token sequences.
pub fn lcs_len<T: AsRef<str>>(a: &[T], b: &[T]) -> usize {
    if a.is_empty() || b.is_empty() {
        return 0;
    }
    let m = a.len();
    let words = m.div_ceil(64);
    let mut masks: HashMap<&str, Vec<u64>> = HashMap::new();
    for (i, t) in a.iter().enumerate() {
        masks.entry(t.as_ref()).or_insert_with(|| vec![0; words])[i / 64] |= 1u64 << (i % 64);
    }
    let mut v = vec![u64::MAX; words];
    if !m.is_multiple_of(64) {
        v[words - 1] = (1u64 << (m % 64)) - 1;
    }
    for t in b {
        let Some(mask) = masks.get(t.as_ref()) else {
            continue;
        };
        let mut carry = 0u64;
        for w in 0..words {
            let u = v[w] & mask[w];
            let (s1, c1) = v[w].overflowing_add(u);
            let (s2, c2) = s1.overflowing_add(carry);
            carry = (c1 as u64) + (c2 as u64);
            v[w] = s2 | (v[w] & !mask[w]);
        }
    }
    if !m.is_multiple_of(64) {
        v[words - 1] &= (1u64 << (m % 64)) - 1;
    }
    let ones: usize = v.iter().map(|w| w.count_ones() as usize).sum();
    m - ones
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dp(a: &[&str], b: &[&str]) -> usize {
        let mut prev = vec![0; b.len() + 1];
        for x in a {
            let mut cur = vec![0; b.len() + 1];
            for (j, y) in b.iter().enumerate() {
                cur[j + 1] = if x == y {
                    prev[j] + 1
                } else {
                    prev[j + 1].max(cur[j])
                };
            }
            prev = cur;
        }
        prev[b.len()]
    }

    #[test]
    fn matches_dynamic_program() {
        let mut state = 12345u64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let alphabet = ["a", "b", "c", "d"];
        for _ in 0..300 {
            let la = (next() % 150) as usize;
            let lb = (next() % 150) as usize;
            let a: Vec<&str> = (0..la).map(|_| alphabet[(next() % 4) as usize]).collect();
            let b: Vec<&str> = (0..lb).map(|_| alphabet[(next() % 4) as usize]).collect();
            assert_eq!(lcs_len(&a, &b), dp(&a, &b));
        }
    }

    #[test]
    fn edge_cases() {
        let e: [&str; 0] = [];
        assert_eq!(lcs_len(&e, &["a"]), 0);
        assert_eq!(lcs_len(&["a", "b"], &["b", "a"]), 1);
        let long: Vec<String> = (0..200).map(|i| i.to_string()).collect();
        assert_eq!(lcs_len(&long, &long), 200);
    }
}
