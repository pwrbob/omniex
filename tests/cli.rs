//! CLI behavior tests.

use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::Value;

const MD5_HASH: &str = "8743b52063cd84097a65d1633f5c74f5";
const SALTED_MD5_HASH: &str = "3d83c8e717ff0e7ecfe187f088d69954:343141";

fn omniex() -> Command {
    Command::cargo_bin("omniex").expect("binary is built")
}

#[test]
fn parse_prints_the_rendered_hash() {
    omniex()
        .args(["parse", MD5_HASH, "--type", "md5"])
        .assert()
        .success()
        .stdout(format!("{MD5_HASH}\n"))
        .stderr("");
}

#[test]
fn parse_supports_john_format() {
    omniex()
        .args(["parse", MD5_HASH, "--type", "md5", "--format", "john"])
        .assert()
        .success()
        .stdout(format!("{MD5_HASH}\n"));
}

#[test]
fn parse_selects_a_type_by_slug() {
    omniex()
        .args(["parse", SALTED_MD5_HASH, "--type", "salted-md5"])
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
        .args(["parse", MD5_HASH, "--type", "md5", "--json"])
        .output()
        .expect("command runs");
    assert!(output.status.success());

    let value: Value = serde_json::from_slice(&output.stdout).expect("valid JSON");
    assert_eq!(value["name"], "MD5");
    assert_eq!(value["slug"], "md5");
    assert_eq!(value["modes"][0]["tool"], "hashcat");
    assert_eq!(value["modes"][0]["mode"], 0);
    assert_eq!(value["fields"][0]["name"], "digest");
    assert_eq!(value["fields"][0]["role"], "digest");
    assert_eq!(value["fields"][0]["encoding"], "hex");
    assert_eq!(value["fields"][0]["value"], MD5_HASH);
}

#[test]
fn parse_verbose_reports_fields() {
    omniex()
        .args(["parse", MD5_HASH, "--type", "md5", "--verbose"])
        .assert()
        .success()
        .stdout(predicate::str::contains("MD5 [md5]"))
        .stdout(predicate::str::contains("field digest [digest, hex]"));
}

#[test]
fn parse_reads_a_hash_list_from_stdin() {
    omniex()
        .args(["parse", "--type", "md5", "--stdin"])
        .write_stdin(format!("{MD5_HASH}\n\n{MD5_HASH}\n"))
        .assert()
        .success()
        .stdout(format!("{MD5_HASH}\n{MD5_HASH}\n"));
}

#[test]
fn parse_reports_the_line_number_and_writes_no_partial_output() {
    omniex()
        .args(["parse", "--type", "md5", "--stdin"])
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
        .stdout("md4\tMD4\nmd5\tMD5\nntlm\tNTLM\n");
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
fn extract_reports_that_no_extractor_exists() {
    omniex()
        .args(["extract", "artifact.bin", "--type", "md5"])
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
fn invalid_release_is_a_usage_error() {
    omniex()
        .args(["parse", MD5_HASH, "--hc-version", "eight"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("invalid release"));
}

#[test]
fn types_lists_available_hash_types() {
    omniex()
        .arg("types")
        .assert()
        .success()
        .stdout(predicate::str::contains("md4\tMD4"))
        .stdout(predicate::str::contains("md5\tMD5"))
        .stdout(predicate::str::contains("salted-md5\tSalted MD5"))
        .stdout(predicate::str::contains("phpass\tphpass"));
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
    assert!(entries[0]["modes"].is_array());
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
