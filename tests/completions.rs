//! COMPLETE-activated shell completion tests.

use assert_cmd::Command;
use predicates::prelude::*;

const MD5_HASH: &str = "8743b52063cd84097a65d1633f5c74f5";

fn omniex() -> Command {
    let mut command = Command::cargo_bin("omniex").expect("binary is built");
    command.env("COLUMNS", "120");
    command
}

/// One completion request: the words being completed follow `--`, and
/// `_CLAP_COMPLETE_INDEX` selects the word the cursor is on, counting the
/// binary name at index 0.
fn complete(index: &str, words: &[&str]) -> Command {
    let mut command = omniex();
    command.env("COMPLETE", "bash");
    command.env("_CLAP_COMPLETE_INDEX", index);
    let mut args = vec!["--"];
    args.extend(words);
    command.args(&args);
    command
}

#[test]
fn bash_registration_names_the_binary() {
    omniex()
        .env("COMPLETE", "bash")
        .assert()
        .success()
        .stderr("")
        .stdout(
            predicate::str::contains("_clap_complete_omniex()").and(predicate::str::contains(
                "complete -o nospace -o bashdefault -o nosort -F _clap_complete_omniex omniex",
            )),
        );
}

#[test]
fn zsh_registration_names_the_binary() {
    omniex()
        .env("COMPLETE", "zsh")
        .assert()
        .success()
        .stderr("")
        .stdout(predicate::str::contains("#compdef omniex"));
}

#[test]
fn fish_registration_names_the_binary() {
    omniex()
        .env("COMPLETE", "fish")
        .assert()
        .success()
        .stderr("")
        .stdout(predicate::str::contains("--command omniex"));
}

#[test]
fn elvish_registration_names_the_binary() {
    omniex()
        .env("COMPLETE", "elvish")
        .assert()
        .success()
        .stderr("")
        .stdout(predicate::str::contains(
            "edit:completion:arg-completer[omniex]",
        ));
}

#[test]
fn powershell_registration_names_the_binary() {
    omniex()
        .env("COMPLETE", "powershell")
        .assert()
        .success()
        .stderr("")
        .stdout(predicate::str::contains(
            "Register-ArgumentCompleter -Native -CommandName omniex",
        ));
}

#[test]
fn parse_type_completes_registered_slugs() {
    complete("3", &["omniex", "parse", "--type", "md"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("md4")
                .and(predicate::str::contains("md5"))
                .and(predicate::str::contains("md5crypt"))
                .and(predicate::str::contains("bcrypt").not()),
        );
}

#[test]
fn extract_type_completes_registered_slugs() {
    complete("3", &["omniex", "extract", "--type", "md5"])
        .assert()
        .success()
        .stdout(predicate::str::contains("md5crypt").and(predicate::str::contains("bcrypt").not()));
}

#[test]
fn show_completes_registered_slugs() {
    complete("2", &["omniex", "show", "md5"])
        .assert()
        .success()
        .stdout(predicate::str::contains("md5crypt").and(predicate::str::contains("bcrypt").not()));
}

#[test]
fn type_completion_without_a_match_is_empty() {
    complete("3", &["omniex", "parse", "--type", "zzzz"])
        .assert()
        .success()
        .stdout("");
}

#[test]
fn subcommand_names_complete() {
    complete("1", &["omniex", "ext"])
        .assert()
        .success()
        .stdout("extract");
}

#[test]
fn flag_names_complete() {
    complete("2", &["omniex", "parse", "--f"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("--file")
                .and(predicate::str::contains("--format"))
                .and(predicate::str::contains("--full")),
        );
}

#[test]
fn artifact_argument_completes_file_paths() {
    complete("2", &["omniex", "extract", "README"])
        .current_dir(std::path::Path::new(env!("CARGO_MANIFEST_DIR")))
        .assert()
        .success()
        .stdout("README.md");
}

#[test]
fn file_argument_completes_file_paths() {
    complete("3", &["omniex", "parse", "--file", "READ"])
        .current_dir(std::path::Path::new(env!("CARGO_MANIFEST_DIR")))
        .assert()
        .success()
        .stdout("README.md");
}

#[test]
fn complete_zero_runs_the_cli_normally() {
    omniex()
        .env("COMPLETE", "0")
        .args(["parse", MD5_HASH, "--type", "md5", "--format", "hash"])
        .assert()
        .success()
        .stdout(format!("{MD5_HASH}\n"));
}

#[test]
fn unset_complete_runs_the_cli_normally() {
    omniex()
        .env_remove("COMPLETE")
        .args(["parse", MD5_HASH, "--type", "md5", "--format", "hash"])
        .assert()
        .success()
        .stdout(format!("{MD5_HASH}\n"));
}

#[test]
fn unknown_shell_is_a_usage_error() {
    omniex()
        .env("COMPLETE", "nonsense")
        .assert()
        .code(2)
        .stdout("")
        .stderr(predicate::str::contains(
            "unknown shell `nonsense`, expected one of `bash`, `elvish`, `fish`, `powershell`, `zsh`",
        ));
}
