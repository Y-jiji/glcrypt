use base64::{Engine, engine::general_purpose::STANDARD};
use std::io::{self, Read, Write};

const PRE: &str = "GLC:";

/// Git clean filter — read all of stdin, encrypt line-by-line, write to stdout \
/// Lines already carrying the `GLC:` prefix are passed through unchanged (idempotent) \
/// O(n) over input; one `seal` call per line
pub fn clean(key: &[u8; 32]) {
    let mut out = io::stdout().lock();
    let mut buf = Vec::new();
    io::stdin().lock().read_to_end(&mut buf).unwrap();
    for seg in buf.split_inclusive(|&b| b == b'\n') {
        let core = seg.strip_suffix(b"\n").unwrap_or(seg);
        let s = std::str::from_utf8(core).unwrap_or("");
        if s.starts_with(PRE) {
            out.write_all(seg).unwrap();
        } else {
            let enc = crate::crypt::seal(key, seg);
            let b64 = STANDARD.encode(&enc);
            write!(out, "{PRE}{b64}\n").unwrap();
        }
    }
}

/// Git smudge filter — read all of `src`, decrypt line-by-line, write to stdout \
/// Unrecognised lines are emitted as-is \
/// O(n) over input; one `open` call per line
pub fn smudge(key: &[u8; 32], src: &mut dyn Read) {
    let mut out = io::stdout().lock();
    let mut buf = Vec::new();
    src.read_to_end(&mut buf).unwrap();
    for raw in buf.split_inclusive(|&b| b == b'\n') {
        out.write_all(&dline(key, raw)).unwrap();
    }
}

/// Decrypt one raw line, returning the original bytes unchanged on any failure \
/// Passes unencrypted lines through so a smudge over mixed content is safe
fn dline(key: &[u8; 32], raw: &[u8]) -> Vec<u8> {
    peel(key, raw).unwrap_or_else(|| raw.to_vec())
}

/// Strip `GLC:` prefix, base64-decode, and decrypt `raw` \
/// `@return`: plaintext if prefix present and auth tag validates, None otherwise
fn peel(key: &[u8; 32], raw: &[u8]) -> Option<Vec<u8>> {
    let s = std::str::from_utf8(raw).ok()?.trim();
    let blob = STANDARD.decode(s.strip_prefix(PRE)?).ok()?;
    crate::crypt::open(key, &blob)
}
