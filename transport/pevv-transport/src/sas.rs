//! Short authentication string for pairing (docs/TRANSPORT.md section 5.1): six words from the
//! BIP-39 English list, derived from both sides' key fingerprints and the invite nonce. Both
//! screens must show the same six words; the approving person compares them.
//!
//! The same derivation shows a device's fingerprint as eight words in the Devices screen.

use bip39::Language;

const SAS_CONTEXT: &str = "PEVV-transport-pairing-sas-v1";
const FP_CONTEXT: &str = "PEVV-transport-fingerprint-words-v1";

fn words(seed: &[u8; 32], count: usize) -> Vec<String> {
    let list = Language::English.word_list();
    // 11 bits per word; take bits from the front of the digest.
    let mut out = Vec::with_capacity(count);
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    let mut it = seed.iter();
    while out.len() < count {
        while bits < 11 {
            // 32 bytes hold 256 bits, enough for 8 words (88 bits).
            let b = it.next().copied().unwrap_or(0);
            acc = (acc << 8) | u32::from(b);
            bits += 8;
        }
        let idx = (acc >> (bits - 11)) & 0x7ff;
        bits -= 11;
        acc &= (1 << bits) - 1;
        out.push(list[idx as usize].to_string());
    }
    out
}

/// The six pairing words, from the **inviter's** key fingerprint, the **joiner's** node id and
/// the invite nonce. Both sides know all three: the joiner read the first and the nonce from
/// the invite, the inviter has its own fingerprint and learns the joiner's node id from the
/// authenticated session.
///
/// TODO(U12): ideally the joiner's key *fingerprint* goes in instead of its node id, which
/// would bind its post-quantum key too. The overlay at the pinned revision gives the inviter
/// no accessor for a peer's key (its state file does not record it for inbound pairings), so
/// the joiner is bound by its Ed25519 node id only.
pub fn sas_words(inviter_fp: &[u8; 32], joiner_node_id: &str, nonce: &[u8]) -> Vec<String> {
    let mut h = blake3::Hasher::new_derive_key(SAS_CONTEXT);
    h.update(inviter_fp);
    let id = joiner_node_id.to_ascii_lowercase();
    h.update(&(id.len() as u32).to_le_bytes());
    h.update(id.as_bytes());
    h.update(&(nonce.len() as u32).to_le_bytes());
    h.update(nonce);
    words(h.finalize().as_bytes(), 6)
}

/// Eight words that stand for a key fingerprint, to compare two screens.
pub fn fingerprint_words(fp: &[u8; 32]) -> Vec<String> {
    let mut h = blake3::Hasher::new_derive_key(FP_CONTEXT);
    h.update(fp);
    words(h.finalize().as_bytes(), 8)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn words_are_stable_and_every_input_matters() {
        let fp = [1u8; 32];
        let id = "ab".repeat(32);
        let n = [9u8; 16];
        let w = sas_words(&fp, &id, &n);
        assert_eq!(w.len(), 6);
        assert_eq!(w, sas_words(&fp, &id.to_uppercase(), &n));
        assert_ne!(w, sas_words(&[2u8; 32], &id, &n));
        assert_ne!(w, sas_words(&fp, &"cd".repeat(32), &n));
        assert_ne!(w, sas_words(&fp, &id, &[8u8; 16]));
        assert_eq!(fingerprint_words(&fp).len(), 8);
    }
}
