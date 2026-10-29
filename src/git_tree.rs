//! Object-level verification of complete, non-truncated GitHub recursive trees.
use std::collections::BTreeMap;

use sha2::Digest;

const MAX_ENTRIES: usize = 100_000;
const MAX_DEPTH: usize = 128;
const MAX_PATH_BYTES: usize = 4096;
const MAX_TOTAL_PATH_BYTES: usize = 16 * 1024 * 1024;

pub(crate) struct GitTreeEntry<'a> {
    pub path: &'a str,
    pub mode: &'a str,
    pub object_type: &'a str,
    pub sha: &'a str,
}

struct Directory<'a> {
    sha: &'a str,
    children: Vec<usize>,
}

enum TreeDigest {
    Sha1(sha1::Sha1),
    Sha256(sha2::Sha256),
}

impl TreeDigest {
    fn new(width: usize) -> Self {
        if width == 40 {
            Self::Sha1(sha1::Sha1::new())
        } else {
            Self::Sha256(sha2::Sha256::new())
        }
    }

    fn update(&mut self, bytes: &[u8]) {
        match self {
            Self::Sha1(hash) => hash.update(bytes),
            Self::Sha256(hash) => hash.update(bytes),
        }
    }

    fn matches(self, expected: &str) -> bool {
        let mut decoded = [0; 32];
        decode_oid(expected, &mut decoded);
        match self {
            Self::Sha1(hash) => hash.finalize()[..] == decoded[..20],
            Self::Sha256(hash) => hash.finalize()[..] == decoded[..32],
        }
    }
}

fn valid_oid(sha: &str, width: usize) -> bool {
    sha.len() == width
        && sha.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

// Only called after validating the complete lower-case hexadecimal identifier.
fn decode_oid(sha: &str, output: &mut [u8; 32]) {
    fn nibble(b: u8) -> u8 {
        if b <= b'9' { b - b'0' } else { b - b'a' + 10 }
    }
    for (pair, byte) in sha.as_bytes().chunks_exact(2).zip(output) {
        *byte = (nibble(pair[0]) << 4) | nibble(pair[1]);
    }
}

fn canonical_mode(entry: &GitTreeEntry<'_>) -> Option<&'static str> {
    match (entry.mode, entry.object_type) {
        ("040000", "tree") => Some("40000"),
        ("100644", "blob") => Some("100644"),
        ("100755", "blob") => Some("100755"),
        ("120000", "blob") => Some("120000"),
        ("160000", "commit") => Some("160000"),
        _ => None,
    }
}

fn split_path(path: &str) -> (&str, &str) {
    path.rsplit_once('/').unwrap_or(("", path))
}

/// Verify every advertised tree object and the root, without fetching blob or
/// submodule contents. The caller must reject a truncated API response first.
/// Limits: 100,000 entries, 128 components/path, 4,096 bytes/path and 16 MiB
/// aggregate path bytes. Paths are exact UTF-8 Git names, not filesystem paths;
/// no Unicode normalization or case folding is performed.
pub(crate) fn verify_recursive_tree<'a>(
    root_sha: &str,
    entries: impl IntoIterator<Item = GitTreeEntry<'a>>,
) -> Result<(), &'static str> {
    let width = root_sha.len();
    if !matches!(width, 40 | 64) || !valid_oid(root_sha, width) {
        return Err("invalid root object identifier");
    }
    let mut nodes = Vec::new();
    let mut owners = BTreeMap::new();
    let mut directories = BTreeMap::new();
    directories.insert("", Directory { sha: root_sha, children: Vec::new() });
    let mut total_path_bytes = 0usize;
    for entry in entries {
        if nodes.len() == MAX_ENTRIES {
            return Err("tree entry limit exceeded");
        }
        total_path_bytes = total_path_bytes.checked_add(entry.path.len())
            .ok_or("tree path size overflow")?;
        if entry.path.is_empty() || entry.path.len() > MAX_PATH_BYTES
            || total_path_bytes > MAX_TOTAL_PATH_BYTES
            || entry.path.contains(['\0', '\\'])
        {
            return Err("invalid or excessive tree path");
        }
        let mut depth = 0;
        for component in entry.path.split('/') {
            depth += 1;
            if component.is_empty() || matches!(component, "." | "..") || depth > MAX_DEPTH {
                return Err("invalid or excessive tree path components");
            }
        }
        if !valid_oid(entry.sha, width) {
            return Err("invalid or foreign object identifier");
        }
        if canonical_mode(&entry).is_none() {
            return Err("invalid tree entry type or mode");
        }
        if owners.insert(entry.path, nodes.len()).is_some() {
            return Err("duplicate tree path ownership");
        }
        if entry.object_type == "tree" {
            directories.insert(entry.path, Directory { sha: entry.sha, children: Vec::new() });
        }
        nodes.push(entry);
    }
    for (index, entry) in nodes.iter().enumerate() {
        let (parent, _) = split_path(entry.path);
        directories.get_mut(parent).ok_or("missing parent directory")?.children.push(index);
    }
    // Reverse lexical path order visits every descendant before its parent.
    for directory in directories.values_mut().rev() {
        directory.children.sort_unstable_by(|&left, &right| {
            let left = &nodes[left];
            let right = &nodes[right];
            let left_name = split_path(left.path).1.as_bytes();
            let right_name = split_path(right.path).1.as_bytes();
            left_name.iter().copied().chain((left.object_type == "tree").then_some(b'/'))
                .cmp(right_name.iter().copied().chain((right.object_type == "tree").then_some(b'/')))
        });
        let mut length = 0usize;
        for &index in &directory.children {
            let entry = &nodes[index];
            let mode = canonical_mode(entry).ok_or("invalid tree entry mode")?;
            length = length.checked_add(mode.len() + 1 + split_path(entry.path).1.len() + 1 + width / 2)
                .ok_or("tree object size overflow")?;
        }
        let mut hash = TreeDigest::new(width);
        hash.update(b"tree ");
        let mut decimal = [0u8; 20];
        let mut start = decimal.len();
        loop {
            start -= 1;
            decimal[start] = b'0' + (length % 10) as u8;
            length /= 10;
            if length == 0 {
                break;
            }
        }
        hash.update(&decimal[start..]);
        hash.update(b"\0");
        for &index in &directory.children {
            let entry = &nodes[index];
            hash.update(canonical_mode(entry).ok_or("invalid tree entry mode")?.as_bytes());
            hash.update(b" ");
            hash.update(split_path(entry.path).1.as_bytes());
            hash.update(b"\0");
            let mut oid = [0; 32];
            decode_oid(entry.sha, &mut oid);
            hash.update(&oid[..width / 2]);
        }
        if !hash.matches(directory.sha) {
            return Err("tree object identifier mismatch");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const EMPTY: &str = "4b825dc642cb6eb9a060e54bf8d69288fbee4904";
    const BLOB: &str = "ce013625030ba8dba906f756967f9e9ca394464a";
    const SUBTREE: &str = "640ba63b141ba35b527fee65e78140148c8d0a5b";
    const ROOT: &str = "17ba6f4f78b8480cfd0746758b08bacb877d0c9c";

    fn entry<'a>(path: &'a str, mode: &'a str, object_type: &'a str, sha: &'a str) -> GitTreeEntry<'a> {
        GitTreeEntry { path, mode, object_type, sha }
    }

    fn nested() -> Vec<GitTreeEntry<'static>> {
        vec![entry("docs/note.txt", "100644", "blob", BLOB), entry("docs", "040000", "tree", SUBTREE)]
    }

    #[test]
    fn fixed_git_objects_and_empty_identity() {
        // Independently encoded Git objects: blob "hello\n", tree containing
        // "100644 note.txt\0" + raw blob ID, then "40000 docs\0" + raw tree ID.
        assert!(verify_recursive_tree(EMPTY, []).is_ok());
        assert!(verify_recursive_tree(ROOT, nested()).is_ok());
        assert!(verify_recursive_tree(ROOT, []).is_err());
        assert!(verify_recursive_tree(EMPTY, nested()).is_err());
    }

    #[test]
    fn rejects_wrong_advertised_objects_and_ownership() {
        for index in 0..2 {
            let mut entries = nested();
            entries[index].sha = EMPTY;
            assert!(verify_recursive_tree(ROOT, entries).is_err());
        }
        let mut entries = nested();
        entries[0].path = "docs/other.txt";
        assert!(verify_recursive_tree(ROOT, entries).is_err());
        let mut entries = nested();
        entries.push(entry("docs", "100644", "blob", BLOB));
        assert!(verify_recursive_tree(ROOT, entries).is_err());
        assert!(verify_recursive_tree(ROOT, [entry("docs/note.txt", "100644", "blob", BLOB)]).is_err());
        let mut entries = nested();
        entries[0].mode = "100755";
        assert!(verify_recursive_tree(ROOT, entries).is_err());
    }

    #[test]
    fn uses_git_directory_slash_sort_order() {
        let entries = [entry("a0", "100644", "blob", BLOB),
            entry("a", "040000", "tree", SUBTREE),
            entry("a/note.txt", "100644", "blob", BLOB),
            entry("a.c", "100644", "blob", BLOB)];
        // Git order is a.c, a/, a0, not plain name order a, a.c, a0.
        assert!(verify_recursive_tree("8af151aad04863ef7b0f9884eaabd37e535264df", entries).is_ok());
    }

    #[test]
    fn executable_symlink_and_submodule_modes_are_preserved() {
        assert!(verify_recursive_tree("afc071eac8451e27cba401df73825f19be71d4f8", [
            entry("module", "160000", "commit", BLOB),
            entry("link", "120000", "blob", BLOB),
            entry("exec", "100755", "blob", BLOB),
        ]).is_ok());
        // An explicitly listed empty directory is a real empty tree object.
        assert!(verify_recursive_tree("f4ec99e8174c01eab488469b4c2680500bbb18da", [entry("empty", "040000", "tree", EMPTY)]).is_ok());
        assert!(verify_recursive_tree(EMPTY, [entry("empty", "040000", "tree", EMPTY)]).is_err());
    }

    #[test]
    fn fixed_sha256_git_objects() {
        assert!(verify_recursive_tree("6ef19b41225c5369f1c104d45d8d85efa9b057b53b14b4b9b939dd74decc5321", []).is_ok());
        assert!(verify_recursive_tree("24b09718d5aaa1bf8b319600327daa45dde9e0341bccb7b1c2cbfdf46fabcd1d", [
            entry("docs", "040000", "tree", "e115762f088c5d68bd48440ad41ca57270f2d920f525f7d4ed1244230bfff18a"),
            entry("docs/note.txt", "100644", "blob", "2cf8d83d9ee29543b34a87727421fdecb7e3f3a183d337639025de576db9ebb4"),
        ]).is_ok());
    }

    #[test]
    fn malformed_modes_paths_and_hashes_refuse() {
        for path in ["", "/a", "a/", "a//b", "./a", "a/../b", "a\0b", "a\\b"] {
            assert!(verify_recursive_tree(EMPTY, [entry(path, "100644", "blob", BLOB)]).is_err());
        }
        for (mode, kind) in [("40000", "tree"), ("100664", "blob"), ("120000", "tree"), ("160000", "blob"), ("100644", "commit")] {
            assert!(verify_recursive_tree(EMPTY, [entry("a", mode, kind, BLOB)]).is_err());
        }
        for sha in ["", "CE013625030ba8dba906f756967f9e9ca394464a", "ge013625030ba8dba906f756967f9e9ca394464a", "6ef19b41225c5369f1c104d45d8d85efa9b057b53b14b4b9b939dd74decc5321"] {
            assert!(verify_recursive_tree(EMPTY, [entry("a", "100644", "blob", sha)]).is_err());
        }
        assert!(verify_recursive_tree("not-a-hash", []).is_err());
    }

    #[test]
    fn bounded_input_refuses() {
        let long = "a".repeat(MAX_PATH_BYTES + 1);
        assert!(verify_recursive_tree(EMPTY, [entry(&long, "100644", "blob", BLOB)]).is_err());
        let deep = vec!["a"; MAX_DEPTH + 1].join("/");
        assert!(verify_recursive_tree(EMPTY, [entry(&deep, "100644", "blob", BLOB)]).is_err());
        let names: Vec<_> = (0..=MAX_ENTRIES).map(|i| format!("f{i}")).collect();
        assert_eq!(verify_recursive_tree(EMPTY, names.iter().map(|name| entry(name, "100644", "blob", BLOB))), Err("tree entry limit exceeded"));
        let prefix = "a".repeat(MAX_PATH_BYTES - 16);
        let names: Vec<_> = (0..5000).map(|i| format!("{prefix}{i}")).collect();
        assert_eq!(verify_recursive_tree(EMPTY, names.iter().map(|name| entry(name, "100644", "blob", BLOB))), Err("invalid or excessive tree path"));
    }
}
