//! Aho-Corasick automaton over bytes (Aho and Corasick, 1975).
//!
//! The patterns are inserted into a trie; a breadth-first pass computes for each node
//! the failure link (the longest proper suffix of its string that is also a trie
//! prefix) and the full goto function, so the search reads each text byte exactly once
//! and reports every pattern occurrence. Output sets are merged along failure links.
//! Search cost is O(n + matches) for a text of n bytes, independent of the number of
//! patterns; construction is O(total pattern length * 256).

use std::collections::VecDeque;

pub struct AhoCorasick {
    goto: Vec<[u32; 256]>,
    out: Vec<Vec<u32>>,
}

impl AhoCorasick {
    /// Build the automaton. Empty patterns are ignored.
    #[allow(clippy::needless_range_loop)] // `b` indexes both a node row and the queue logic
    pub fn new<P: AsRef<[u8]>>(patterns: &[P]) -> Self {
        let mut goto: Vec<[u32; 256]> = vec![[u32::MAX; 256]];
        let mut out: Vec<Vec<u32>> = vec![Vec::new()];
        for (pi, p) in patterns.iter().enumerate() {
            let p = p.as_ref();
            if p.is_empty() {
                continue;
            }
            let mut s = 0usize;
            for &b in p {
                let next = goto[s][b as usize];
                s = if next == u32::MAX {
                    goto.push([u32::MAX; 256]);
                    out.push(Vec::new());
                    let id = (goto.len() - 1) as u32;
                    goto[s][b as usize] = id;
                    id as usize
                } else {
                    next as usize
                };
            }
            out[s].push(pi as u32);
        }
        let mut fail = vec![0u32; goto.len()];
        let mut queue = VecDeque::new();
        for b in 0..256 {
            let t = goto[0][b];
            if t == u32::MAX {
                goto[0][b] = 0;
            } else {
                fail[t as usize] = 0;
                queue.push_back(t as usize);
            }
        }
        while let Some(s) = queue.pop_front() {
            let f = fail[s] as usize;
            let inherited = out[f].clone();
            out[s].extend(inherited);
            for b in 0..256 {
                let t = goto[s][b];
                if t == u32::MAX {
                    goto[s][b] = goto[f][b];
                } else {
                    fail[t as usize] = goto[f][b];
                    queue.push_back(t as usize);
                }
            }
        }
        AhoCorasick { goto, out }
    }

    /// For each pattern index, whether it occurs in `text`.
    pub fn present(&self, text: &[u8], n_patterns: usize) -> Vec<bool> {
        let mut seen = vec![false; n_patterns];
        let mut s = 0usize;
        for &b in text {
            s = self.goto[s][b as usize] as usize;
            for &p in &self.out[s] {
                seen[p as usize] = true;
            }
        }
        seen
    }

    /// Every `(pattern index, end offset)` occurrence in `text`.
    pub fn find_all(&self, text: &[u8]) -> Vec<(usize, usize)> {
        let mut hits = Vec::new();
        let mut s = 0usize;
        for (i, &b) in text.iter().enumerate() {
            s = self.goto[s][b as usize] as usize;
            for &p in &self.out[s] {
                hits.push((p as usize, i + 1));
            }
        }
        hits
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn naive(text: &str, pats: &[&str]) -> Vec<bool> {
        pats.iter()
            .map(|p| !p.is_empty() && text.contains(p))
            .collect()
    }

    #[test]
    fn classic_example() {
        let pats = ["he", "she", "his", "hers"];
        let ac = AhoCorasick::new(&pats);
        let mut hits = ac.find_all(b"ushers");
        hits.sort();
        assert_eq!(hits, vec![(0, 4), (1, 4), (3, 6)]);
    }

    #[test]
    fn agrees_with_substring_search() {
        let pats = ["abc", "bca", "", "zz", "a", "cab", "abcabc"];
        let texts = ["", "abcabc", "zzz", "xyz", "bcab", "aaaa"];
        let ac = AhoCorasick::new(&pats);
        for t in texts {
            assert_eq!(ac.present(t.as_bytes(), pats.len()), naive(t, &pats), "{t}");
        }
    }
}
