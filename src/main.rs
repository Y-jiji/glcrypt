mod crypt;
mod filter;
mod gitcfg;
mod key;

use clap::{Parser, Subcommand};

/// Top-level CLI — optional passcode override and a required subcommand \
/// `pwd`: if set, key is derived from this passcode instead of loaded from git config
#[derive(Parser)]
struct Cli {
    #[arg(long)]
    pwd: Option<String>,
    #[command(subcommand)]
    cmd: Cmd,
}

/// Subcommand dispatch \
/// `Init`: prompt for passcode, derive key, store in git config, configure filter \
/// `Clean`: encrypt stdin to stdout (registered as git clean filter) \
/// `Smudge`: decrypt to stdout from stdin or an optional file path (textconv support)
#[derive(Subcommand)]
enum Cmd {
    Init,
    Clean,
    Smudge {
        /// file to read instead of stdin (used by textconv)
        file: Option<String>,
    },
}

/// Parse CLI args and dispatch to the appropriate subcommand handler
fn main() {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Init => key::keygen(),
        Cmd::Clean => filter::clean(&getkey(cli.pwd)),
        Cmd::Smudge { file } => {
            let k = getkey(cli.pwd);
            match file {
                Some(p) => {
                    let mut f = std::fs::File::open(&p).unwrap();
                    filter::smudge(&k, &mut f);
                }
                None => {
                    let sin = std::io::stdin();
                    filter::smudge(&k, &mut sin.lock());
                }
            }
        }
    }
}

/// Resolve the encryption key: derive from `pwd` when given, else load from git config \
/// Exits the process with an error message if neither source yields a key
fn getkey(pwd: Option<String>) -> [u8; 32] {
    match pwd {
        Some(p) => key::derive(&p),
        None => key::load().unwrap_or_else(|| {
            eprintln!("no key; run glcrypt init");
            std::process::exit(1);
        }),
    }
}

