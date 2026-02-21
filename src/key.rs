use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use std::io::{self, Write};
use std::process::Command;

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

fn prompt(msg: &str) -> String {
    eprint!("{msg}");
    io::stderr().flush().unwrap();
    let mut s = String::new();
    io::stdin().read_line(&mut s).unwrap();
    s.trim_end().to_string()
}

pub fn keygen() {
    let pwd = prompt("passcode: ");
    let chk = prompt("confirm: ");
    if pwd != chk {
        eprintln!("mismatch");
        std::process::exit(1);
    }
    let mut k = [0u8; 32];
    pbkdf2_hmac::<Sha256>(
        pwd.as_bytes(),
        b"glcrypt",
        600_000,
        &mut k,
    );
    let hx = hex::encode(k);
    let st = Command::new("git")
        .args(["config", "glcrypt.key", &hx])
        .status()
        .expect("git config failed");
    if !st.success() {
        eprintln!("git config failed");
        std::process::exit(1);
    }
    eprintln!("key stored");
    crate::gitcfg::init();
    let _ = Command::new("git")
        .args(["rm", "--cached", "-rq", "."])
        .status();
    let _ = Command::new("git")
        .args(["reset", "--hard"])
        .status();
}
