use base64::{Engine, engine::general_purpose::STANDARD};
use std::io::{self, Read, Write};

const PRE: &str = "GLC:";
const RAW: &str = "GLCRAW:";

pub fn clean(key: &[u8; 32]) {
    let mut out = io::stdout().lock();
    let mut buf = Vec::new();
    io::stdin().lock().read_to_end(&mut buf).unwrap();
    if is_bin(&buf) {
        let enc = crate::crypt::seal(key, &buf);
        let b64 = STANDARD.encode(&enc);
        write!(out, "{RAW}{b64}\n").unwrap();
        return;
    }
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

pub fn smudge(key: &[u8; 32], src: &mut dyn Read) {
    let mut out = io::stdout().lock();
    let mut buf = Vec::new();
    src.read_to_end(&mut buf).unwrap();
    let s = std::str::from_utf8(&buf).unwrap_or("");
    if let Some(pt) = dblob(key, s.trim_end()) {
        out.write_all(&pt).unwrap();
        return;
    }
    for raw in buf.split(|&b| b == b'\n') {
        if raw.is_empty() { continue; }
        out.write_all(&dline(key, raw)).unwrap();
    }
}

fn dblob(key: &[u8; 32], s: &str) -> Option<Vec<u8>> {
    let b64 = s.strip_prefix(RAW)?;
    let blob = STANDARD.decode(b64).ok()?;
    crate::crypt::open(key, &blob)
}

fn dline(key: &[u8; 32], raw: &[u8]) -> Vec<u8> {
    peel(key, raw).unwrap_or_else(|| raw.to_vec())
}

fn peel(key: &[u8; 32], raw: &[u8]) -> Option<Vec<u8>> {
    let s = std::str::from_utf8(raw).ok()?.trim();
    let blob = STANDARD.decode(s.strip_prefix(PRE)?).ok()?;
    crate::crypt::open(key, &blob)
}

fn is_bin(d: &[u8]) -> bool {
    let end = d.len().min(8192);
    d[..end].contains(&0)
}
