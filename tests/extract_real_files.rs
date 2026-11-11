//! Integration tests that create real artifacts with external tools.

mod common;

use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;

use assert_cmd::Command;

fn omniex() -> assert_cmd::Command {
    let mut command = Command::cargo_bin("omniex").expect("binary is built");
    command.env("COLUMNS", "120");
    command
}

fn john_run() -> PathBuf {
    if let Some(dir) = std::env::var_os("OMNIEX_JOHN_RUN") {
        return PathBuf::from(dir);
    }
    let john = std::env::var_os("OMNIEX_JOHN").expect("OMNIEX_JOHN or OMNIEX_JOHN_RUN");
    Path::new(&john)
        .parent()
        .expect("John run directory")
        .to_path_buf()
}

fn normalize_zip2(stdout: &str) -> Vec<String> {
    stdout
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            let start = line.find('$')?;
            let hash = &line[start..];
            let end = hash.find("$/zip2$")? + "$/zip2$".len();
            Some(hash[..end].to_owned())
        })
        .collect()
}

#[test]
#[ignore = "requires 7z and the John zip2john binary"]
fn generates_a_real_aes_zip_and_matches_zip2john() {
    let root = Path::new(env!("CARGO_TARGET_TMPDIR")).join("real-aes-zip");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("secret.txt"), b"real integration test secret\n").unwrap();

    let mut command = ProcessCommand::new("7z");
    command.current_dir(&root).args([
        "a",
        "-tzip",
        "-mem=AES256",
        "-ppassword",
        "archive.zip",
        "secret.txt",
    ]);
    let status = common::timed_status(&mut command).expect("run 7z");
    assert!(status.success());

    let mut command = omniex();
    command
        .args(["extract", "--type", "winzip"])
        .arg(root.join("archive.zip"));
    let output = common::timed_assert_output(&mut command).unwrap();
    assert!(output.status.success());
    let ours = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect::<Vec<_>>();

    let mut command = ProcessCommand::new(john_run().join("zip2john"));
    command.arg(root.join("archive.zip"));
    let reference = common::timed_output(&mut command).unwrap();
    assert!(reference.status.success());
    let reference = normalize_zip2(&String::from_utf8_lossy(&reference.stdout));
    assert_eq!(ours, reference);
}
