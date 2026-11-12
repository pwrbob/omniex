//! CLI behavior tests.

use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::Value;

const MD5_HASH: &str = "8743b52063cd84097a65d1633f5c74f5";
const SALTED_MD5_HASH: &str = "3d83c8e717ff0e7ecfe187f088d69954:343141";

fn omniex() -> Command {
    let mut command = Command::cargo_bin("omniex").expect("binary is built");
    command.env("COLUMNS", "120");
    command
}

#[test]
fn parse_prints_the_rendered_hash() {
    omniex()
        .args(["parse", MD5_HASH, "--type", "md5", "--format", "hash"])
        .assert()
        .success()
        .stdout(format!("{MD5_HASH}\n"))
        .stderr("");
}

#[test]
fn parse_supports_john_format() {
    omniex()
        .args([
            "parse", MD5_HASH, "--type", "md5", "--tool", "john", "--format", "hash",
        ])
        .assert()
        .success()
        .stdout(format!("{MD5_HASH}\n"));
}

#[test]
fn parse_selects_a_type_by_slug() {
    omniex()
        .args([
            "parse",
            SALTED_MD5_HASH,
            "--type",
            "salted-md5",
            "--format",
            "hash",
        ])
        .assert()
        .success()
        .stdout(format!("{SALTED_MD5_HASH}\n"));
}

#[test]
fn parse_rejects_an_unknown_type_as_usage_error() {
    omniex()
        .args(["parse", MD5_HASH, "--type", "nope"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("unknown hash type `nope`"));
}

#[test]
fn parse_reports_a_bad_hash() {
    omniex()
        .args(["parse", "not-a-hash"])
        .assert()
        .code(1)
        .stdout("")
        .stderr(predicate::str::contains("no hash type matched"));
}

#[test]
fn parse_json_has_the_pinned_shape() {
    let output = omniex()
        .args(["parse", MD5_HASH, "--type", "md5", "--format", "json"])
        .output()
        .expect("command runs");
    assert!(output.status.success());

    let value: Value = serde_json::from_slice(&output.stdout).expect("valid JSON");
    let entries = value.as_array().expect("array");
    assert_eq!(entries.len(), 1);
    let entry = &entries[0];
    assert_eq!(entry["name"], "MD5");
    assert_eq!(entry["slug"], "md5");
    assert_eq!(entry["line"], 1);
    assert_eq!(entry["input"], MD5_HASH);
    assert_eq!(
        entry["hashcat"],
        serde_json::json!([0, 70, 2600, 3500, 4300, 4400])
    );
    assert_eq!(entry["john"], serde_json::json!(["Raw-MD5", "Raw-MD5u"]));
    assert_eq!(entry["fields"][0]["name"], "digest");
    assert_eq!(entry["fields"][0]["role"], "digest");
    assert_eq!(entry["fields"][0]["encoding"], "hex");
    assert_eq!(entry["fields"][0]["value"], MD5_HASH);
}

#[test]
fn parse_verbose_reports_fields() {
    omniex()
        .args(["parse", MD5_HASH, "--type", "md5"])
        .assert()
        .success()
        .stdout(predicate::str::contains("MD5 (md5)"))
        .stdout(predicate::str::contains("Hashcat"))
        .stdout(predicate::str::contains("Fields"))
        .stdout(predicate::str::contains("digest"))
        .stdout(predicate::str::contains("16-byte MD5 digest"));
}

#[test]
fn parse_verbose_truncates_long_values_unless_full_is_requested() {
    omniex()
        .env("COLUMNS", "40")
        .args(["parse", MD5_HASH, "--type", "md5"])
        .assert()
        .success()
        .stdout(predicate::str::contains(" ... "))
        .stdout(predicate::str::contains(MD5_HASH).not());

    omniex()
        .env("COLUMNS", "120")
        .args(["parse", MD5_HASH, "--type", "md5", "--full"])
        .assert()
        .success()
        .stdout(predicate::str::contains(MD5_HASH));
}

#[test]
fn parse_reads_a_hash_list_from_stdin() {
    omniex()
        .args(["parse", "--type", "md5", "--stdin", "--format", "hash"])
        .write_stdin(format!("{MD5_HASH}\n\n{MD5_HASH}\n"))
        .assert()
        .success()
        .stdout(format!("{MD5_HASH}\n{MD5_HASH}\n"));
}

#[test]
fn parse_reports_the_line_number_and_writes_no_partial_output() {
    omniex()
        .args(["parse", "--type", "md5", "--stdin", "--format", "hash"])
        .write_stdin(format!("{MD5_HASH}\nbad\n"))
        .assert()
        .code(1)
        .stdout("")
        .stderr(predicate::str::contains("line 2:"));
}

#[test]
fn identify_lists_the_matching_type() {
    omniex()
        .args(["identify", MD5_HASH])
        .assert()
        .success()
        .stdout(predicate::str::contains(format!("Input: {MD5_HASH}")))
        .stdout(predicate::str::contains("Slug"))
        .stdout(predicate::str::contains("md4"))
        .stdout(predicate::str::contains("MD4"))
        .stdout(predicate::str::contains("900"))
        .stdout(predicate::str::contains("Raw-MD4"))
        .stdout(predicate::str::contains("─"));
}

#[test]
fn identify_fails_when_nothing_matches() {
    omniex()
        .args(["identify", "not-a-hash"])
        .assert()
        .code(1)
        .stdout("")
        .stderr(predicate::str::contains("no hash type matched"));
}

#[test]
fn extract_supports_human_output_and_validates_full() {
    let artifact = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/artifacts/dpapi/masterkey.bin");

    omniex()
        .args(["extract", "--type", "dpapi"])
        .arg(&artifact)
        .args(["--format", "human"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Artifact:"))
        .stdout(predicate::str::contains("Fields"));

    omniex()
        .args(["extract", "--type", "dpapi"])
        .arg(&artifact)
        .args(["--format", "json", "--full"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("--full requires --format human"));
}

#[test]
fn extract_reports_that_no_extractor_exists() {
    omniex()
        .args(["extract", "artifact.bin", "--type", "chacha20"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("no extractor is registered"));
}

#[test]
fn missing_input_is_a_usage_error() {
    omniex()
        .args(["parse", "--type", "md5"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("provide a hash"));
}

#[test]
fn removed_hc_version_option_is_a_usage_error() {
    omniex()
        .args(["parse", MD5_HASH, "--hc-version", "8.0.0"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("unexpected argument"));
}

#[test]
fn types_lists_available_hash_types() {
    omniex()
        .arg("types")
        .assert()
        .success()
        .stdout(predicate::str::contains("Hash types ("))
        .stdout(predicate::str::contains("Slug"))
        .stdout(predicate::str::contains("md4"))
        .stdout(predicate::str::contains("MD4"))
        .stdout(predicate::str::contains("900"))
        .stdout(predicate::str::contains("Raw-MD4"))
        .stdout(predicate::str::contains("salted-md5"))
        .stdout(predicate::str::contains("Salted MD5"))
        .stdout(predicate::str::contains("phpass"));
}

#[test]
fn types_json_is_an_array_of_descriptors() {
    let output = omniex()
        .args(["types", "--json"])
        .output()
        .expect("command runs");
    assert!(output.status.success());

    let value: Value = serde_json::from_slice(&output.stdout).expect("valid JSON");
    let entries = value.as_array().expect("array");
    assert!(entries.len() >= 20);
    assert_eq!(entries[0]["slug"], "md4");
    assert!(entries[0]["fields"].is_array());
    assert!(entries[0]["hashcat"].is_array());
    assert!(entries[0]["john"].is_array());
}

#[test]
fn identify_json_is_an_array_of_matches() {
    let output = omniex()
        .args(["identify", MD5_HASH, "--json"])
        .output()
        .expect("command runs");
    assert!(output.status.success());

    let value: Value = serde_json::from_slice(&output.stdout).expect("valid JSON");
    let entries = value.as_array().expect("array");
    assert!(entries.len() >= 3);
    assert_eq!(entries[0]["line"], 1);
    assert_eq!(entries[0]["input"], MD5_HASH);
    assert_eq!(entries[0]["slug"], "md4");
    assert_eq!(entries[0]["hashcat"], serde_json::json!([900]));
    assert_eq!(entries[0]["john"], serde_json::json!(["Raw-MD4"]));
}

#[test]
fn human_tables_have_one_rule_and_no_tabs() {
    let output = omniex().arg("types").output().expect("command runs");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(!stdout.contains('\t'));
    assert_eq!(
        stdout.lines().filter(|line| line.starts_with('─')).count(),
        1
    );
    assert!(stdout.lines().any(|line| line.starts_with("Slug")));
    assert!(!stdout.lines().any(|line| line.starts_with("SLUG")));
}

#[test]
fn long_mode_lists_wrap_to_the_terminal_width() {
    let mut command = Command::cargo_bin("omniex").expect("binary is built");
    command.env("COLUMNS", "60");
    let output = command.arg("types").output().expect("command runs");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.lines().all(|line| line.chars().count() <= 60));
}

#[test]
fn parse_reports_ambiguity_between_md4_and_md5() {
    omniex()
        .args(["parse", MD5_HASH])
        .assert()
        .code(1)
        .stdout("")
        .stderr(predicate::str::contains("ambiguous hash type"))
        .stderr(predicate::str::contains("md4"))
        .stderr(predicate::str::contains("md5"));
}

#[test]
fn parse_json_is_an_array_for_multiple_inputs() {
    let output = omniex()
        .args(["parse", "--type", "md5", "--stdin", "--format", "json"])
        .write_stdin(format!("{MD5_HASH}\n{MD5_HASH}\n"))
        .output()
        .expect("command runs");
    assert!(output.status.success());

    let value: Value = serde_json::from_slice(&output.stdout).expect("valid JSON");
    let entries = value.as_array().expect("array");
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0]["line"], 1);
    assert_eq!(entries[1]["line"], 2);
}

#[test]
fn show_reports_one_type_without_a_hash() {
    omniex()
        .args(["show", "oracle-h"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Oracle H (oracle-h)"))
        .stdout(predicate::str::contains("Hashcat: 3100 / John: -"))
        .stdout(predicate::str::contains("digest"))
        .stdout(predicate::str::contains("salt"))
        .stdout(predicate::str::contains("Decimal salt"));
}

#[test]
fn show_json_is_one_descriptor_object() {
    let output = omniex()
        .args(["show", "oracle-h", "--json"])
        .output()
        .expect("command runs");
    assert!(output.status.success());

    let value: Value = serde_json::from_slice(&output.stdout).expect("valid JSON");
    assert!(value.is_object());
    assert_eq!(value["slug"], "oracle-h");
    assert_eq!(value["hashcat"], serde_json::json!([3100]));
    assert_eq!(value["fields"][0]["name"], "digest");
    assert_eq!(value["fields"][1]["name"], "salt");
}

#[test]
fn show_rejects_an_unknown_type_as_usage_error() {
    omniex()
        .args(["show", "not-a-type"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("unknown hash type"));
}

#[test]
fn parse_reads_files_with_crlf_line_endings() {
    let path = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("crlf-hashes.txt");
    std::fs::write(&path, format!("{MD5_HASH}\r\n\r\n{MD5_HASH}\r\n")).expect("write fixture");

    omniex()
        .args(["parse", "--type", "md5", "--file"])
        .arg(&path)
        .args(["--format", "hash"])
        .assert()
        .success()
        .stdout(format!("{MD5_HASH}\n{MD5_HASH}\n"));
}

#[test]
fn identify_json_reports_only_modes_valid_for_the_value() {
    let digest = "0".repeat(32);
    let salt = "a".repeat(300);
    let hash = format!("{digest}:{salt}");
    let output = omniex()
        .args(["identify", "--json", &hash])
        .output()
        .expect("command runs");
    assert!(output.status.success());
    let value: Value = serde_json::from_slice(&output.stdout).expect("valid JSON");
    let entry = &value.as_array().expect("array")[0];
    assert_eq!(entry["slug"], "salted-md5");
    assert_eq!(entry["hashcat"], serde_json::json!([]));
}

#[test]
fn parse_rejects_rendering_for_an_unsupported_tool() {
    omniex()
        .args([
            "parse",
            SALTED_MD5_HASH,
            "--type",
            "salted-md5",
            "--tool",
            "john",
            "--format",
            "hash",
        ])
        .assert()
        .code(1)
        .stdout("")
        .stderr(predicate::str::contains("no compatible John format"));
}
