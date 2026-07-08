use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit, Nonce,
    aead::Aead,
};
use hmac::{Hmac, Mac};
use sha2::Sha256;

type H = Hmac<Sha256>;

/// HMAC-SHA256 deterministic nonce derivation — same key+data always yields the same 12 bytes \
/// `key`: HMAC secret (the encryption key) \
/// `data`: plaintext; determinism makes the clean filter idempotent \
/// `@return`: first 12 bytes of HMAC output, used directly as ChaCha20Poly1305 nonce \
/// O(|data|) one HMAC pass; no heap allocation beyond the 12-byte array
pub fn dnonce(key: &[u8; 32], data: &[u8]) -> [u8; 12] {
    let mut mac = <H as KeyInit>::new_from_slice(key).unwrap();
    mac.update(data);
    let res = mac.finalize().into_bytes();
    let mut n = [0u8; 12];
    n.copy_from_slice(&res[..12]);
    n
}

/// Encrypt `pt` with ChaCha20Poly1305 and prepend the deterministic nonce \
/// `@return`: `[nonce(12B)] ++ [ciphertext+Poly1305 tag]`; identical plaintext → identical output \
/// O(|pt|) one-pass; one Vec allocation sized nonce + ciphertext + 16-byte tag
pub fn seal(key: &[u8; 32], pt: &[u8]) -> Vec<u8> {
    let n = dnonce(key, pt);
    let ciph = ChaCha20Poly1305::new(key.into());
    let ct = ciph.encrypt(Nonce::from_slice(&n), pt).unwrap();
    [n.as_slice(), &ct].concat()
}

/// Decrypt a blob produced by `seal`; authenticate before returning plaintext \
/// `blob`: `[nonce(12B)] ++ [ciphertext+tag]`; must be ≥ 13 bytes \
/// `@return`: plaintext on auth success, None on tag mismatch or truncated input \
/// O(|blob|) one-pass; one Vec allocation for plaintext
pub fn open(key: &[u8; 32], blob: &[u8]) -> Option<Vec<u8>> {
    if blob.len() < 12 {
        return None;
    }
    let (n, ct) = blob.split_at(12);
    let ciph = ChaCha20Poly1305::new(key.into());
    ciph.decrypt(Nonce::from_slice(n), ct).ok()
}
