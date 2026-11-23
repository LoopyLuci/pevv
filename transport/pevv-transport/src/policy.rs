//! Pure sync policy: the compare-and-swap on `rev`, fork detection and the allow-list
//! (docs/TRANSPORT.md sections 4.2, 6.6; rules R2, T2, T3). No I/O, no clock.

use std::collections::HashSet;
use std::sync::Arc;

use parking_lot::RwLock;

/// What a device holds of a vault: revision and the SHA-256 (hex) of the sealed file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Head {
    /// Monotonic revision.
    pub rev: u64,
    /// SHA-256 hex of the sealed file.
    pub hash: String,
}

/// What to do with a peer's ANNOUNCE.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Same revision, same hash: nothing to do.
    InSync,
    /// The peer is ahead: fetch its file.
    Fetch,
    /// We are ahead: the peer will fetch (or be pushed to). Never adopt a lower `rev`.
    Ahead,
    /// Same revision, different hash (T3): fetch the peer's copy and resolve deterministically.
    Fork,
}

/// Decide on an announced head. `None` local means "nothing held".
pub fn decide(local: Option<&Head>, remote: &Head) -> Decision {
    match local {
        None => Decision::Fetch,
        Some(l) if remote.rev > l.rev => Decision::Fetch,
        Some(l) if remote.rev < l.rev => Decision::Ahead,
        Some(l) if remote.hash == l.hash => Decision::InSync,
        Some(_) => Decision::Fork,
    }
}

/// Deterministic tiebreak for a fork: both sides must pick the same file, so the higher hash
/// wins. Hex of equal length compares like the bytes. The loser is kept by the store.
pub fn fork_remote_wins(local_hash: &str, remote_hash: &str) -> bool {
    remote_hash > local_hash
}

/// What to do with a PUSH (T2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushVerdict {
    /// The receiver is exactly at `base`: replace.
    Apply,
    /// The receiver already holds exactly this file (idempotent retry).
    AlreadyHave,
    /// The receiver is not at `base` (ahead or behind): the sender must fetch and reconcile.
    Stale,
    /// Same revision, different file.
    Fork,
    /// `rev` does not advance past `base`.
    Invalid,
}

/// Decide on a PUSH `{base, rev, hash}` against what we hold.
pub fn push_verdict(local: Option<&Head>, base: u64, rev: u64, hash: &str) -> PushVerdict {
    if rev <= base {
        return PushVerdict::Invalid;
    }
    let local_rev = local.map_or(0, |l| l.rev);
    if local_rev == base {
        return PushVerdict::Apply;
    }
    match local {
        Some(l) if l.rev == rev && l.hash == hash => PushVerdict::AlreadyHave,
        Some(l) if l.rev == rev => PushVerdict::Fork,
        _ => PushVerdict::Stale,
    }
}

/// The set of node ids that may open the PSP service. Derived from the sealed roster (never
/// from a wildcard), cached by the host; cloneable handle, safe to share across tasks.
#[derive(Debug, Clone, Default)]
pub struct AllowList {
    nodes: Arc<RwLock<HashSet<String>>>,
}

impl AllowList {
    /// An empty list: nobody is allowed.
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the whole list (recomputed on every vault write).
    pub fn set<I: IntoIterator<Item = String>>(&self, nodes: I) {
        *self.nodes.write() = nodes.into_iter().map(|n| n.to_lowercase()).collect();
    }

    /// Allow one node (after the person approved the pairing).
    pub fn allow(&self, node: &str) {
        self.nodes.write().insert(node.to_lowercase());
    }

    /// Remove nodes at once (ROSTER_HINT and revocation can only restrict).
    pub fn revoke<'a, I: IntoIterator<Item = &'a str>>(&self, nodes: I) {
        let mut g = self.nodes.write();
        for n in nodes {
            g.remove(&n.to_lowercase());
        }
    }

    /// Whether `node` may sync.
    pub fn permits(&self, node: &str) -> bool {
        self.nodes.read().contains(&node.to_lowercase())
    }

    /// A snapshot, sorted.
    pub fn list(&self) -> Vec<String> {
        let mut v: Vec<String> = self.nodes.read().iter().cloned().collect();
        v.sort();
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(rev: u64, hash: &str) -> Head {
        Head {
            rev,
            hash: hash.into(),
        }
    }

    #[test]
    fn decision_table() {
        assert_eq!(decide(None, &h(1, "a")), Decision::Fetch);
        assert_eq!(decide(Some(&h(1, "a")), &h(2, "b")), Decision::Fetch);
        assert_eq!(decide(Some(&h(3, "a")), &h(2, "b")), Decision::Ahead);
        assert_eq!(decide(Some(&h(2, "a")), &h(2, "a")), Decision::InSync);
        assert_eq!(decide(Some(&h(2, "a")), &h(2, "b")), Decision::Fork);
    }

    #[test]
    fn fork_tiebreak_is_symmetric() {
        assert!(fork_remote_wins("aa", "bb"));
        assert!(!fork_remote_wins("bb", "aa"));
    }

    #[test]
    fn push_cas_table() {
        let l = h(5, "x");
        assert_eq!(push_verdict(Some(&l), 5, 6, "y"), PushVerdict::Apply);
        assert_eq!(push_verdict(None, 0, 1, "y"), PushVerdict::Apply);
        assert_eq!(push_verdict(Some(&l), 4, 5, "x"), PushVerdict::AlreadyHave);
        assert_eq!(push_verdict(Some(&l), 4, 5, "z"), PushVerdict::Fork);
        assert_eq!(push_verdict(Some(&l), 3, 4, "z"), PushVerdict::Stale);
        assert_eq!(push_verdict(Some(&l), 6, 7, "z"), PushVerdict::Stale);
        assert_eq!(push_verdict(None, 2, 3, "z"), PushVerdict::Stale);
        assert_eq!(push_verdict(Some(&l), 5, 5, "z"), PushVerdict::Invalid);
        assert_eq!(push_verdict(Some(&l), 5, 4, "z"), PushVerdict::Invalid);
    }

    #[test]
    fn allow_list_is_explicit_and_revocation_wins() {
        let a = AllowList::new();
        assert!(!a.permits("AB"));
        a.set(["ab".to_string(), "cd".to_string()]);
        assert!(a.permits("AB"));
        a.revoke(["ab"]);
        assert!(!a.permits("ab"));
        assert_eq!(a.list(), vec!["cd".to_string()]);
    }
}
