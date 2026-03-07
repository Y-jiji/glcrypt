mod crypt;
mod filter;
mod gitcfg;
mod key;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let (k, cmd, rest) = parse(&args);
    match cmd {
        "clean" => filter::clean(&k),
        "smudge" => smudge(&k, rest),
        "init" => key::keygen(),
        _ => {
            eprintln!("usage: glcrypt [--key HEX] <clean|smudge|init>");
            std::process::exit(1);
        }
    }
}

fn parse(args: &[String]) -> ([u8; 32], &str, Option<String>) {
    let (hx, off) = match args.get(1).map(|s| s.as_str()) {
        Some("--key") => (args.get(2), 3),
        _ => (None, 1),
    };
    let cmd = args.get(off).map(|s| s.as_str()).unwrap_or("");
    let rest = args.get(off + 1).cloned();
    let k = match hx {
        Some(h) => hexkey(h),
        None => need_key(),
    };
    (k, cmd, rest)
}

fn hexkey(h: &str) -> [u8; 32] {
    let b = hex::decode(h).unwrap_or_else(|_| {
        eprintln!("bad hex key");
        std::process::exit(1);
    });
    if b.len() != 32 {
        eprintln!("key must be 32 bytes");
        std::process::exit(1);
    }
    let mut k = [0u8; 32];
    k.copy_from_slice(&b);
    k
}

fn need_key() -> [u8; 32] {
    match key::load() {
        Some(k) => k,
        None => {
            eprintln!("no key; run glcrypt init");
            std::process::exit(1);
        }
    }
}

fn smudge(k: &[u8; 32], path: Option<String>) {
    match path {
        Some(p) => {
            let mut f = std::fs::File::open(&p).unwrap();
            filter::smudge(k, &mut f);
        }
        None => {
            let sin = std::io::stdin();
            filter::smudge(k, &mut sin.lock());
        }
    }
}
