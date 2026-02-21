use std::fs;
use std::process::{Command, ExitStatus};

pub fn gitcli(args: &[&str]) -> ExitStatus {
    let out = Command::new("git")
        .args(args)
        .output()
        .expect("git failed");
    for b in [&out.stdout, &out.stderr] {
        let s = String::from_utf8_lossy(b);
        for ln in s.lines() {
            eprintln!("[GIT] {ln}");
        }
    }
    out.status
}

pub fn init() {
    let exe = std::env::current_exe().unwrap();
    let bin = exe.to_str().unwrap();
    let cln = format!("{bin} clean");
    let smg = format!("{bin} smudge");
    gitcli(&["config", "filter.glcrypt.clean", &cln]);
    gitcli(&["config", "filter.glcrypt.smudge", &smg]);
    gitcli(&["config", "filter.glcrypt.required", "true"]);
    gitcli(&["config", "diff.glcrypt.textconv", &smg]);
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
