use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit, Nonce,
    aead::Aead,
};
use hmac::{Hmac, Mac};
use sha2::Sha256;

type H = Hmac<Sha256>;

pub fn dnonce(key: &[u8; 32], data: &[u8]) -> [u8; 12] {
    let mut mac = <H as KeyInit>::new_from_slice(key).unwrap();
    mac.update(data);
    let res = mac.finalize().into_bytes();
    let mut n = [0u8; 12];
    n.copy_from_slice(&res[..12]);
    n
}

pub fn seal(key: &[u8; 32], pt: &[u8]) -> Vec<u8> {
    let n = dnonce(key, pt);
    let ciph = ChaCha20Poly1305::new(key.into());
    let ct = ciph.encrypt(Nonce::from_slice(&n), pt).unwrap();
    [n.as_slice(), &ct].concat()
}

pub fn open(key: &[u8; 32], blob: &[u8]) -> Option<Vec<u8>> {
    if blob.len() < 12 {
        return None;
    }
    let (n, ct) = blob.split_at(12);
    let ciph = ChaCha20Poly1305::new(key.into());
    ciph.decrypt(Nonce::from_slice(n), ct).ok()
}
