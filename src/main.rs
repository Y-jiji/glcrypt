mod crypt;
mod filter;
mod gitcfg;
mod key;

fn main() {
    let cmd = std::env::args().nth(1).unwrap_or_default();
    match cmd.as_str() {
        "clean" => {
            let k = need_key();
            filter::clean(&k);
        }
        "smudge" => {
            let k = need_key();
            let arg = std::env::args().nth(2);
            smudge(&k, arg);
        }
        "init" => key::keygen(),
        _ => {
            eprintln!("usage: glcrypt <clean|smudge|init>");
            std::process::exit(1);
        }
    }
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
