use std::fs;
use std::process::Command;

pub fn init() {
    let exe = std::env::current_exe().unwrap();
    let bin = exe.to_str().unwrap();
    let cln = format!("{bin} clean");
    let smg = format!("{bin} smudge");
    cfg("filter.glcrypt.clean", &cln);
    cfg("filter.glcrypt.smudge", &smg);
    cfg("filter.glcrypt.required", "true");
    cfg("diff.glcrypt.textconv", &smg);
    let path = ".gitattributes";
    let rules = "* filter=glcrypt diff=glcrypt\n\
                  .git* !filter !diff\n";
    let content = fs::read_to_string(path).unwrap_or_default();
    if !content.contains("filter=glcrypt") {
        fs::write(path, content + rules).unwrap();
        eprintln!(".gitattributes updated");
    }
    eprintln!("filter configured");
}

fn cfg(k: &str, v: &str) {
    let st = Command::new("git")
        .args(["config", k, v])
        .status()
        .expect("git failed");
    if !st.success() {
        eprintln!("git config {k} failed");
        std::process::exit(1);
    }
}
