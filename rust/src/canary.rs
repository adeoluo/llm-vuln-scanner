//! Canary search across all views; mirrors `llm_vuln_scanner.matching.find_canaries_py`.

use crate::aho::AhoCorasick;
use crate::views::{VIEW_ORDER, skeleton, unleet, views};

/// Shortest skeleton a canary needs before the normalized views are searched.
pub const MIN_SKELETON: usize = 6;

/// The pattern for each view (by [`VIEW_ORDER`] position); `None` where not searched.
pub fn patterns_for(canary: &str) -> Vec<Option<String>> {
    let sk = skeleton(canary);
    let mut pats = vec![None; VIEW_ORDER.len()];
    pats[0] = Some(canary.to_lowercase());
    if sk.chars().count() >= MIN_SKELETON {
        for p in pats.iter_mut().take(7).skip(1) {
            *p = Some(sk.clone());
        }
        pats[7] = Some(skeleton(&unleet(canary)));
    }
    pats
}

/// `(canary index, view name)` for each canary found, first matching view only.
pub fn find_canaries(text: &str, canaries: &[String]) -> Vec<(usize, &'static str)> {
    if text.is_empty() || canaries.is_empty() {
        return Vec::new();
    }
    let vs = views(text);
    let per_canary: Vec<Vec<Option<String>>> = canaries
        .iter()
        .map(|c| {
            if c.is_empty() {
                vec![None; VIEW_ORDER.len()]
            } else {
                patterns_for(c)
            }
        })
        .collect();
    let mut found: Vec<Option<&'static str>> = vec![None; canaries.len()];
    for (vi, view) in vs.iter().enumerate() {
        let Some(view) = view else { continue };
        let pats: Vec<&str> = per_canary
            .iter()
            .map(|p| p[vi].as_deref().unwrap_or(""))
            .collect();
        let ac = AhoCorasick::new(&pats);
        for (ci, hit) in ac
            .present(view.as_bytes(), pats.len())
            .into_iter()
            .enumerate()
        {
            if hit && found[ci].is_none() {
                found[ci] = Some(VIEW_ORDER[vi]);
            }
        }
    }
    found
        .into_iter()
        .enumerate()
        .filter_map(|(i, v)| v.map(|name| (i, name)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_raw_and_encoded() {
        let c = vec![
            "LVS-7F3A-PELICAN".to_string(),
            "LVS-0000-OSPREY".to_string(),
        ];
        assert_eq!(find_canaries("ok lvs-7f3a-pelican", &c), vec![(0, "raw")]);
        assert_eq!(
            find_canaries("NACILEP-A3F7-SVL and L V S 0 0 0 0 O S P R E Y", &c),
            vec![(0, "reversed"), (1, "skeleton")]
        );
        assert!(find_canaries("", &c).is_empty());
        assert!(find_canaries("ab", &["".to_string(), "ab".to_string()]) == vec![(1, "raw")]);
    }
}
