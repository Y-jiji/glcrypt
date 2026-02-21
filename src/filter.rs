use base64::{Engine, engine::general_purpose::STANDARD};
use std::io::{self, Read, Write};

const PRE: &str = "GLC:";
const RAW: &str = "GLCRAW:";

pub fn clean(key: &[u8; 32]) {
    let sin = io::stdin();
    let sout = io::stdout();
    let mut out = sout.lock();
    let mut buf = Vec::new();
    sin.lock().read_to_end(&mut buf).unwrap();
    if is_bin(&buf) {
        let enc = crate::crypt::seal(key, &buf);
        let b64 = STANDARD.encode(&enc);
        write!(out, "{RAW}{b64}\n").unwrap();
        return;
    }
    for raw in buf.split(|&b| b == b'\n') {
        let line = strip_cr(raw);
        if line.is_empty() && raw.is_empty() {
            continue;
        }
        let s = std::str::from_utf8(line).unwrap_or("");
        if s.starts_with(PRE) {
            out.write_all(line).unwrap();
        } else {
            let enc = crate::crypt::seal(key, line);
            let b64 = STANDARD.encode(&enc);
            write!(out, "{PRE}{b64}").unwrap();
        }
        if raw.last() == Some(&b'\r') {
            out.write_all(b"\r").unwrap();
        }
        out.write_all(b"\n").unwrap();
    }
}

pub fn smudge(key: &[u8; 32], src: &mut dyn Read) {
    let sout = io::stdout();
    let mut out = sout.lock();
    let mut buf = Vec::new();
    src.read_to_end(&mut buf).unwrap();
    let s = std::str::from_utf8(&buf).unwrap_or("");
    if let Some(pt) = dblob(key, s.trim_end()) {
        out.write_all(&pt).unwrap();
        return;
    }
    for raw in buf.split(|&b| b == b'\n') {
        let line = strip_cr(raw);
        let ls = std::str::from_utf8(line).unwrap_or("");
        let dec = decode(key, line, ls);
        if dec.is_empty() && raw.is_empty() {
            continue;
        }
        out.write_all(&dec).unwrap();
        if raw.last() == Some(&b'\r') {
            out.write_all(b"\r").unwrap();
        }
        out.write_all(b"\n").unwrap();
    }
}

fn dblob(key: &[u8; 32], s: &str) -> Option<Vec<u8>> {
    let b64 = s.strip_prefix(RAW)?;
    let blob = STANDARD.decode(b64).ok()?;
    crate::crypt::open(key, &blob)
}

fn decode(key: &[u8; 32], raw: &[u8], s: &str) -> Vec<u8> {
    let b64 = match s.strip_prefix(PRE) {
        Some(v) => v,
        None => return raw.to_vec(),
    };
    let blob = match STANDARD.decode(b64) {
        Ok(v) => v,
        Err(_) => return raw.to_vec(),
    };
    match crate::crypt::open(key, &blob) {
        Some(pt) => pt,
        None => raw.to_vec(),
    }
}

fn is_bin(d: &[u8]) -> bool {
    let end = d.len().min(8192);
    d[..end].contains(&0)
}

fn strip_cr(d: &[u8]) -> &[u8] {
    d.strip_suffix(b"\r").unwrap_or(d)
}
