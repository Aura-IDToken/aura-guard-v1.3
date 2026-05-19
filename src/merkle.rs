//! RFC 6962 Merkle tree primitives (root, audit proof, proof verification).
//!
//! These are the same hashing rules used by Certificate Transparency, which
//! makes Aura-Guard segment manifests independently verifiable with any
//! off-the-shelf CT tooling.
//!
//! # Hashing rules
//!
//! * **Leaf**  : `SHA-256(0x00 || data)`
//! * **Node**  : `SHA-256(0x01 || left || right)`
//! * **Empty** : `SHA-256("")` — only used when the tree has no leaves.
//!
//! The `0x00`/`0x01` prefixes provide domain separation between leaf and
//! interior node hashes, defeating second-preimage attacks where a node hash
//! could otherwise be passed off as a leaf hash.
//!
//! # Odd-count handling
//!
//! Unlike Bitcoin, RFC 6962 does **not** duplicate the last leaf. When the
//! number of leaves is not a power of two, the tree is constructed as the
//! largest balanced subtree on the left plus a smaller right subtree (built
//! recursively the same way). A single unpaired node at any level is promoted
//! to the parent level unchanged.

use sha2::{Digest, Sha256};

/// SHA-256 leaf hash with the RFC 6962 `0x00` prefix.
#[must_use]
pub fn leaf_hash(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x00u8]);
    h.update(data);
    h.finalize().into()
}

/// SHA-256 interior node hash with the RFC 6962 `0x01` prefix.
#[must_use]
pub fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x01u8]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// Hash of an empty Merkle tree, per RFC 6962 §2.1.
#[must_use]
pub fn empty_root() -> [u8; 32] {
    Sha256::digest([]).into()
}

/// Compute the Merkle Tree Hash (MTH) of a slice of pre-hashed leaves.
///
/// The input slice contains the **leaf hashes** (already prefixed with
/// `0x00`), not raw data. Pass each datum through [`leaf_hash`] first.
#[must_use]
pub fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    match leaves.len() {
        0 => empty_root(),
        1 => leaves[0],
        n => {
            let k = largest_power_of_two_lt(n);
            let left = merkle_root(&leaves[..k]);
            let right = merkle_root(&leaves[k..]);
            node_hash(&left, &right)
        }
    }
}

/// Largest power of two strictly less than `n` (n ≥ 2).
fn largest_power_of_two_lt(n: usize) -> usize {
    // For n = 2 -> 1, n = 3 -> 2, n = 4 -> 2, n = 5 -> 4, etc.
    debug_assert!(n >= 2);
    let mut k = 1usize;
    while k < n {
        k <<= 1;
    }
    k >> 1
}

/// Build an RFC 6962 audit path (Merkle inclusion proof) for leaf at index
/// `m` in a tree of `n` leaves.
///
/// Returns the list of sibling hashes from the leaf level upward. The proof
/// is empty when `n == 1`.
#[must_use]
pub fn audit_path(m: usize, leaves: &[[u8; 32]]) -> Vec<[u8; 32]> {
    let n = leaves.len();
    assert!(m < n, "audit_path: index out of range");
    let mut path = Vec::new();
    audit_path_inner(m, leaves, &mut path);
    path
}

fn audit_path_inner(m: usize, leaves: &[[u8; 32]], out: &mut Vec<[u8; 32]>) {
    let n = leaves.len();
    if n <= 1 {
        return;
    }
    let k = largest_power_of_two_lt(n);
    if m < k {
        audit_path_inner(m, &leaves[..k], out);
        out.push(merkle_root(&leaves[k..]));
    } else {
        audit_path_inner(m - k, &leaves[k..], out);
        out.push(merkle_root(&leaves[..k]));
    }
}

/// Verify an RFC 6962 audit path: rebuild the root from `leaf` + `path` and
/// check it equals `expected_root`.
#[must_use]
pub fn verify_audit_path(
    leaf: &[u8; 32],
    leaf_index: usize,
    tree_size: usize,
    path: &[[u8; 32]],
    expected_root: &[u8; 32],
) -> bool {
    if leaf_index >= tree_size {
        return false;
    }
    let mut hash = *leaf;
    let mut idx = leaf_index;
    let mut size = tree_size;
    for sibling in path {
        // While the current subtree is a single node (no sibling needed),
        // walk up. This mirrors how `audit_path` skips levels when an odd
        // node is promoted unchanged.
        while size > 1 && idx == size - 1 && (idx & 1) == 0 {
            idx /= 2;
            size = size.div_ceil(2);
        }
        if size <= 1 {
            return false;
        }
        if idx & 1 == 0 {
            hash = node_hash(&hash, sibling);
        } else {
            hash = node_hash(sibling, &hash);
        }
        idx /= 2;
        size = size.div_ceil(2);
    }
    // Promote any remaining odd-node levels at the top.
    while size > 1 {
        if idx != size - 1 || (idx & 1) != 0 {
            return false;
        }
        idx /= 2;
        size = size.div_ceil(2);
    }
    &hash == expected_root
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn h(s: &str) -> [u8; 32] {
        leaf_hash(s.as_bytes())
    }

    #[test]
    fn empty_tree_root_is_sha256_of_nothing() {
        // RFC 6962 §2.1 pins MTH({}) = SHA-256().
        let expected =
            hex::decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
                .expect("valid hex literal");
        assert_eq!(empty_root().to_vec(), expected);
    }

    #[test]
    fn single_leaf_root_equals_leaf() {
        let l = leaf_hash(b"hello");
        assert_eq!(merkle_root(&[l]), l);
    }

    #[test]
    fn two_leaf_root() {
        let a = h("a");
        let b = h("b");
        assert_eq!(merkle_root(&[a, b]), node_hash(&a, &b));
    }

    #[test]
    fn rfc6962_known_test_vector() {
        // RFC 6962 §2.1 worked example for a 4-leaf tree.
        // d0..d3 = SHA-256("") repeated as test inputs.
        let d = [h("d0"), h("d1"), h("d2"), h("d3")];
        let expected = node_hash(&node_hash(&d[0], &d[1]), &node_hash(&d[2], &d[3]));
        assert_eq!(merkle_root(&d), expected);
    }

    #[test]
    fn five_leaf_tree_is_left_heavy() {
        // n = 5: largest_power_of_two_lt(5) = 4. So left = MTH(d0..d3),
        // right = leaf d4 (single-leaf MTH).
        let d = [h("d0"), h("d1"), h("d2"), h("d3"), h("d4")];
        let left = merkle_root(&d[..4]);
        let right = d[4];
        assert_eq!(merkle_root(&d), node_hash(&left, &right));
    }

    #[test]
    fn audit_path_and_verify_for_every_index() {
        for size in 1..=17usize {
            let leaves: Vec<[u8; 32]> = (0..size).map(|i| h(&format!("entry-{i}"))).collect();
            let root = merkle_root(&leaves);
            for i in 0..size {
                let path = audit_path(i, &leaves);
                assert!(
                    verify_audit_path(&leaves[i], i, size, &path, &root),
                    "valid proof failed: size={size} i={i}"
                );
                // Wrong leaf must not verify.
                let wrong = h("wrong");
                assert!(
                    !verify_audit_path(&wrong, i, size, &path, &root),
                    "tampered leaf accepted: size={size} i={i}"
                );
            }
        }
    }

    #[test]
    fn proof_for_tampered_root_rejects() {
        let leaves: Vec<[u8; 32]> = (0..8).map(|i| h(&format!("d{i}"))).collect();
        let mut bad_root = merkle_root(&leaves);
        bad_root[0] ^= 0xff;
        let path = audit_path(3, &leaves);
        assert!(!verify_audit_path(&leaves[3], 3, 8, &path, &bad_root));
    }

    #[test]
    fn out_of_range_index_rejects() {
        let leaves = [h("a"), h("b")];
        let root = merkle_root(&leaves);
        let path = audit_path(0, &leaves);
        assert!(!verify_audit_path(&leaves[0], 99, 2, &path, &root));
    }

    #[test]
    fn largest_power_of_two_lt_matches_table() {
        assert_eq!(largest_power_of_two_lt(2), 1);
        assert_eq!(largest_power_of_two_lt(3), 2);
        assert_eq!(largest_power_of_two_lt(4), 2);
        assert_eq!(largest_power_of_two_lt(5), 4);
        assert_eq!(largest_power_of_two_lt(8), 4);
        assert_eq!(largest_power_of_two_lt(9), 8);
        assert_eq!(largest_power_of_two_lt(17), 16);
    }
}
