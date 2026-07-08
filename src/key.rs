use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use std::io::{self, Write};
use std::process::Command;
use crate::gitcfg::gitcli;

/// Read the 32-byte hex-encoded key from `glcrypt.key` in git config \
/// `@return`: the key on success; None if the config entry is absent, non-UTF-8, or not 32 bytes \
/// One `git config` subprocess; no allocation on the None path
pub fn load() -> Option<[u8; 32]> {
    let out = Command::new("git")
        .args(["config", "glcrypt.key"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?;
    let b = hex::decode(s.trim()).ok()?;
    if b.len() != 32 {
        return None;
    }
    let mut k = [0u8; 32];
    k.copy_from_slice(&b);
    Some(k)
}

/// Print `msg` to stderr and read one trimmed line from stdin \
/// Flushes stderr before blocking so the prompt appears before the cursor
fn prompt(msg: &str) -> String {
    eprint!("{msg}");
    io::stderr().flush().unwrap();
    let mut s = String::new();
    io::stdin().read_line(&mut s).unwrap();
    s.trim_end().to_string()
}

/// Derive a 32-byte key from `pwd` via PBKDF2-HMAC-SHA256 with 600 000 iterations \
/// Fixed salt `b"glcrypt"` keeps derivation deterministic across machines (shared-secret \
/// workflow — portability matters more than per-user salt uniqueness) \
/// 600 000 iterations matches the OWASP 2023 recommendation for SHA-256; CPU-bound
pub fn derive(pwd: &str) -> [u8; 32] {
    let mut k = [0u8; 32];
    pbkdf2_hmac::<Sha256>(
        pwd.as_bytes(),
        b"glcrypt",
        600_000,
        &mut k,
    );
    k
}

/// Interactive setup: prompt for passcode twice, derive key, store in git config, \
/// configure the filter, then re-encrypt all tracked files \
/// `git rm --cached -rq .` + `git reset --hard` force every tracked file through the \
/// clean filter so it is encrypted under the newly stored key
pub fn keygen() {
    let pwd = prompt("passcode: ");
    let chk = prompt("confirm: ");
    if pwd != chk {
        eprintln!("mismatch");
        std::process::exit(1);
    }
    let hx = hex::encode(derive(&pwd));
    let st = gitcli(&["config", "glcrypt.key", &hx]);
    if !st.success() {
        std::process::exit(1);
    }
    eprintln!("key stored");
    crate::gitcfg::init();
    gitcli(&["rm", "--cached", "-rq", "."]);
    gitcli(&["reset", "--hard"]);
}
