//! 1Password, Bitwarden, LastPass, and application store extraction.

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use omniex::extract::{self, Artifact, MemorySource, Probe};
use omniex::{Mode, RenderOptions, Tool};

fn fixture(kind: &str, name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/artifacts")
        .join(kind)
        .join(name)
}

fn artifact(kind: &str, name: &str) -> Artifact {
    Artifact::from_bytes(name, std::fs::read(fixture(kind, name)).unwrap())
}

fn with_members(kind: &str, name: &str, members: &[(&str, &str)]) -> Artifact {
    let mut artifact = artifact(kind, name);
    for (member, file) in members {
        artifact = artifact.with_member(
            *member,
            MemorySource::from(std::fs::read(fixture(kind, file)).unwrap()),
        );
    }
    artifact
}

fn omniex() -> Command {
    let mut command = Command::cargo_bin("omniex").expect("binary is built");
    command.env("COLUMNS", "120");
    command
}

macro_rules! extractor {
    ($slug:expr) => {
        match extract::by_slug($slug) {
            Some(extractor) => extractor,
            None => return,
        }
    };
}

fn registered(slug: &str) -> bool {
    extract::by_slug(slug).is_some()
}

fn expected(kind: &str, name: &str) -> String {
    std::fs::read_to_string(fixture(kind, name))
        .unwrap()
        .trim_end()
        .to_owned()
}

fn john(value: &dyn omniex::HashValue) -> String {
    value
        .render(&RenderOptions {
            tool: Tool::John,
            ..RenderOptions::default()
        })
        .unwrap()
}

#[test]
fn onepassword_cloud_extracts_the_hashcat_serialization() {
    let extractor = extractor!("onepassword-cloud");
    assert!(extractor.exact());
    assert!(matches!(
        extractor.probe(&artifact("onepassword-cloud", "profile.js")),
        Probe::Yes(reason) if reason == "1Password cloudkeychain profile"
    ));
    let hashes = extractor
        .extract(&artifact("onepassword-cloud", "profile.js"))
        .expect("extract");
    assert_eq!(hashes.len(), 1);
    assert_eq!(
        hashes[0].render(&RenderOptions::default()).unwrap(),
        expected("onepassword-cloud", "profile.hash")
    );
    assert!(hashes[0].modes().contains(&Mode::Hashcat(8200)));
}

#[test]
fn onepassword_cloud_rejects_bad_profiles() {
    let extractor = extractor!("onepassword-cloud");
    assert_eq!(
        extractor.probe(&Artifact::from_bytes("profile.js", b"not json".to_vec())),
        Probe::No
    );
    assert_eq!(
        extractor.probe(&Artifact::from_bytes("empty.js", Vec::new())),
        Probe::No
    );
    assert!(
        extractor
            .extract(&Artifact::from_bytes(
                "truncated.js",
                br#"{"salt":"AAAA","iterations":40000,"masterKey":"b3BkYXRhMDE="}"#.to_vec()
            ))
            .is_err()
    );
}

#[test]
fn onepassword_cloud_is_ambiguous_with_cloudkeychain() {
    if !registered("onepassword-cloud") {
        return;
    }
    let output = omniex()
        .arg("extract")
        .arg(fixture("onepassword-cloud", "profile.js"))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("ambiguous artifact"), "{stderr}");
    assert!(stderr.contains("cloudkeychain"), "{stderr}");
    assert!(stderr.contains("onepassword-cloud"), "{stderr}");

    let explicit = omniex()
        .args(["extract", "--type", "onepassword-cloud"])
        .arg(fixture("onepassword-cloud", "profile.js"))
        .output()
        .unwrap();
    assert!(explicit.status.success());
    assert_eq!(
        String::from_utf8_lossy(&explicit.stdout).trim_end(),
        expected("onepassword-cloud", "profile.hash")
    );
}

#[test]
fn onepassword_mobile_extracts_every_account() {
    let extractor = extractor!("onepassword-mobile");
    assert!(extractor.exact());
    assert!(matches!(
        extractor.probe(&artifact("onepassword-mobile", "account.json")),
        Probe::Yes(reason) if reason == "1Password mobile keychain accounts"
    ));
    let hashes = extractor
        .extract(&artifact("onepassword-mobile", "account.json"))
        .expect("extract");
    assert_eq!(hashes.len(), 1);
    assert_eq!(
        hashes[0].render(&RenderOptions::default()).unwrap(),
        expected("onepassword-mobile", "account.hash")
    );
    assert!(hashes[0].modes().contains(&Mode::Hashcat(31800)));

    let mut document: serde_json::Value = serde_json::from_slice(
        &std::fs::read(fixture("onepassword-mobile", "account.json")).unwrap(),
    )
    .unwrap();
    let mut second = document["accounts"][0].clone();
    second["email"] = serde_json::Value::String("other@hashcat.net".to_owned());
    document["accounts"].as_array_mut().unwrap().push(second);
    let hashes = extractor
        .extract(&Artifact::from_bytes(
            "accounts.json",
            serde_json::to_vec(&document).unwrap(),
        ))
        .expect("extract");
    assert_eq!(hashes.len(), 2);
    assert_eq!(
        hashes[1].render(&RenderOptions::default()).unwrap(),
        expected("onepassword-mobile", "account.hash")
            .replace("31800@hashcat.net", "other@hashcat.net")
    );
}

#[test]
fn onepassword_mobile_rejects_incomplete_records() {
    let extractor = extractor!("onepassword-mobile");
    for data in [
        br#"{"accounts":[]}"#.to_vec(),
        br#"{"accounts":[{"email":"a@b.c"}]}"#.to_vec(),
        br#"{"accounts":[{"email":"a@b.c","hkdf_salt":"00","hkdf_key":"00","iterations":1,"iv":"00","ciphertext":"00","tag":"00"}]}"#.to_vec(),
        b"not json".to_vec(),
    ] {
        assert_eq!(
            extractor.probe(&Artifact::from_bytes("bad.json", data)),
            Probe::No
        );
    }
}

#[test]
fn bitwarden_extracts_and_scans_every_account() {
    let extractor = extractor!("bitwarden");
    assert!(extractor.exact());
    assert!(matches!(
        extractor.probe(&artifact("bitwarden", "data.json")),
        Probe::Yes(reason) if reason == "Bitwarden local account data"
    ));
    let hashes = extractor
        .extract(&artifact("bitwarden", "data.json"))
        .expect("extract");
    assert_eq!(hashes.len(), 1);
    assert_eq!(
        hashes[0].render(&RenderOptions::default()).unwrap(),
        expected("bitwarden", "data.hash")
    );
    assert!(hashes[0].modes().contains(&Mode::Hashcat(23400)));

    let hashes = extractor
        .extract(&artifact("bitwarden", "multi.json"))
        .expect("extract");
    let rendered = hashes
        .iter()
        .map(|hash| hash.render(&RenderOptions::default()).unwrap())
        .collect::<Vec<_>>()
        .join("\n");
    assert_eq!(rendered, expected("bitwarden", "multi.hash"));
}

#[test]
fn bitwarden_rejects_exports_without_a_master_key_hash() {
    let extractor = extractor!("bitwarden");
    for data in [
        br#"{"encrypted":true,"passwordProtected":true,"kdfType":0,"kdfIterations":100000,"salt":"c2FsdA==","data":"ZGF0YQ=="}"#.to_vec(),
        b"not json".to_vec(),
        Vec::new(),
    ] {
        assert_eq!(
            extractor.probe(&Artifact::from_bytes("export.json", data)),
            Probe::No
        );
    }
}

#[test]
fn lastpass_extracts_the_encu_record() {
    let extractor = extractor!("lastpass");
    let artifact = with_members(
        "lastpass",
        "vault.lpb64",
        &[
            ("username", "username.txt"),
            ("iterations", "iterations.txt"),
        ],
    );
    assert!(matches!(
        extractor.probe(&artifact),
        Probe::Yes(reason) if reason == "LastPass vault ENCU record"
    ));
    let hashes = extractor.extract(&artifact).expect("extract");
    assert_eq!(hashes.len(), 1);
    assert_eq!(
        hashes[0].render(&RenderOptions::default()).unwrap(),
        expected("lastpass", "vault.hash")
    );
    assert!(hashes[0].modes().contains(&Mode::Hashcat(6800)));
}

#[test]
fn lastpass_requires_username_and_iterations() {
    let extractor = extractor!("lastpass");
    let artifact = artifact("lastpass", "vault.lpb64");
    assert!(matches!(
        extractor.probe(&artifact),
        Probe::Maybe(reason) if reason.contains("companions")
    ));
    assert!(extractor.extract(&artifact).is_err());

    let output = omniex()
        .args(["extract", "--type", "lastpass"])
        .arg(fixture("lastpass", "vault.lpb64"))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("missing LastPass username"));

    let auto = omniex()
        .arg("extract")
        .arg(fixture("lastpass", "vault.lpb64"))
        .output()
        .unwrap();
    assert_eq!(auto.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&auto.stderr).contains("has no reliable signature"));
}

#[test]
fn lastpass_rejects_broken_vaults() {
    let extractor = extractor!("lastpass");
    assert_eq!(
        extractor.probe(&Artifact::from_bytes("empty", Vec::new())),
        Probe::No
    );
    assert_eq!(
        extractor.probe(&Artifact::from_bytes("bad", b"not a vault".to_vec())),
        Probe::No
    );
    let truncated = b"LPB64".to_vec();
    assert!(
        extractor
            .extract(&Artifact::from_bytes("truncated", truncated))
            .is_err()
    );

    let mut blob = b"LPAV".to_vec();
    blob.extend_from_slice(&3u32.to_be_bytes());
    blob.extend_from_slice(b"ENC");
    assert_eq!(
        extractor.probe(&Artifact::from_bytes("truncated", blob)),
        Probe::No
    );
}

#[test]
fn lpcli_extracts_the_cli_state() {
    let extractor = extractor!("lpcli");
    let artifact = with_members(
        "lpcli",
        "verify.bin",
        &[
            ("username", "username.txt"),
            ("iterations", "iterations.txt"),
        ],
    );
    assert!(matches!(
        extractor.probe(&artifact),
        Probe::Yes(reason) if reason == "LastPass CLI verify file"
    ));
    let hashes = extractor.extract(&artifact).expect("extract");
    assert_eq!(hashes.len(), 1);
    assert_eq!(john(hashes[0].as_ref()), expected("lpcli", "verify.hash"));
    assert!(hashes[0].modes().contains(&Mode::John("lpcli")));
}

#[test]
fn lpcli_requires_companions_and_a_complete_verify_file() {
    let extractor = extractor!("lpcli");
    let artifact = artifact("lpcli", "verify.bin");
    assert!(matches!(
        extractor.probe(&artifact),
        Probe::Maybe(reason) if reason.contains("companions")
    ));
    assert!(extractor.extract(&artifact).is_err());

    assert_eq!(
        extractor.probe(&Artifact::from_bytes("short", vec![0; 63])),
        Probe::No
    );
    assert_eq!(
        extractor.probe(&Artifact::from_bytes("empty", Vec::new())),
        Probe::No
    );

    let output = omniex()
        .args(["extract", "--type", "lpcli", "--format", "john"])
        .arg(fixture("lpcli", "verify.bin"))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("missing LastPass CLI username"));
}

#[test]
fn signatureless_extractors_need_an_explicit_type() {
    if !registered("lpcli") {
        return;
    }
    let output = omniex()
        .arg("extract")
        .arg(fixture("lpcli", "verify.bin"))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("has no reliable signature"));
}

#[test]
fn signal_extracts_android_secure_preferences() {
    let extractor = extractor!("signal");
    assert!(extractor.exact());
    assert!(matches!(
        extractor.probe(&artifact("signal", "SecureSMS-Preferences.xml")),
        Probe::Yes(reason) if reason == "Signal Android secure preferences"
    ));
    let hashes = extractor
        .extract(&artifact("signal", "SecureSMS-Preferences.xml"))
        .expect("extract");
    assert_eq!(hashes.len(), 1);
    assert_eq!(john(hashes[0].as_ref()), expected("signal", "prefs.hash"));
    assert!(hashes[0].modes().contains(&Mode::John("Signal")));
}

#[test]
fn signal_scans_every_preference_map() {
    let extractor = extractor!("signal");
    let artifact = artifact("signal", "multi.xml");
    let hashes = extractor.extract(&artifact).expect("extract");
    let rendered = hashes
        .iter()
        .map(|hash| john(hash.as_ref()))
        .collect::<Vec<_>>()
        .join("\n");
    assert_eq!(rendered, expected("signal", "multi.hash"));
}

#[test]
fn signal_rejects_non_preferences_and_incomplete_maps() {
    let extractor = extractor!("signal");
    for data in [
        Vec::new(),
        b"not xml".to_vec(),
        br#"<map><boolean value="false"/><int value="6024"/></map>"#.to_vec(),
        br#"<map><boolean value="true"/><int value="6024"/></map>"#.to_vec(),
    ] {
        assert_eq!(
            extractor.probe(&Artifact::from_bytes("prefs.xml", data.clone())),
            Probe::No
        );
        assert!(
            extractor
                .extract(&Artifact::from_bytes("prefs.xml", data))
                .is_err()
        );
    }
}

#[test]
fn telegram_extracts_desktop_local_storage() {
    let extractor = extractor!("telegram");
    assert!(extractor.exact());
    assert!(matches!(
        extractor.probe(&artifact("telegram", "map0")),
        Probe::Yes(reason) if reason == "Telegram Desktop local storage map"
    ));
    let hashes = extractor
        .extract(&artifact("telegram", "map0"))
        .expect("extract");
    assert_eq!(hashes.len(), 1);
    assert_eq!(
        hashes[0].render(&RenderOptions::default()).unwrap(),
        expected("telegram", "map0.hash")
    );
    assert!(hashes[0].modes().contains(&Mode::Hashcat(22600)));
}

#[test]
fn telegram_scans_the_whole_artifact() {
    let extractor = extractor!("telegram");
    let map = std::fs::read(fixture("telegram", "map0")).unwrap();
    let mut data = b"leading bytes that are not a map\n".to_vec();
    data.extend_from_slice(&map);
    data.extend_from_slice(&map);
    let hashes = extractor
        .extract(&Artifact::from_bytes("combined.map", data))
        .expect("extract");
    assert_eq!(hashes.len(), 2);
    assert_eq!(
        hashes[1].render(&RenderOptions::default()).unwrap(),
        expected("telegram", "map0.hash")
    );
}

#[test]
fn telegram_rejects_other_files_and_truncated_maps() {
    let extractor = extractor!("telegram");
    for data in [
        Vec::new(),
        b"not a telegram map".to_vec(),
        b"TDF$".to_vec(),
        b"TDF$\0\0\0\0".to_vec(),
    ] {
        assert_eq!(
            extractor.probe(&Artifact::from_bytes("map0", data.clone())),
            Probe::No
        );
        assert!(
            extractor
                .extract(&Artifact::from_bytes("map0", data))
                .is_err()
        );
    }
}

#[test]
fn flask_session_extracts_a_signed_cookie() {
    let extractor = extractor!("flask-session");
    assert!(extractor.exact());
    assert!(matches!(
        extractor.probe(&artifact("flask-session", "request.txt")),
        Probe::Yes(reason) if reason == "Flask signed session cookie"
    ));
    let hashes = extractor
        .extract(&artifact("flask-session", "request.txt"))
        .expect("extract");
    assert_eq!(hashes.len(), 1);
    assert_eq!(
        hashes[0].render(&RenderOptions::default()).unwrap(),
        expected("flask-session", "session.hash")
    );
    assert!(hashes[0].modes().contains(&Mode::Hashcat(40056)));
}

#[test]
fn flask_session_scans_every_cookie() {
    let extractor = extractor!("flask-session");
    let hashes = extractor
        .extract(&artifact("flask-session", "multi.txt"))
        .expect("extract");
    let rendered = hashes
        .iter()
        .map(|hash| hash.render(&RenderOptions::default()).unwrap())
        .collect::<Vec<_>>()
        .join("\n");
    assert_eq!(rendered, expected("flask-session", "multi.hash"));
}

#[test]
fn flask_session_rejects_unsigned_values() {
    let extractor = extractor!("flask-session");
    for data in [
        Vec::new(),
        b"Cookie: session=not-a-cookie".to_vec(),
        b"Cookie: session=eyJ1c2VyIjoiYSJ9.YjdgRQ.short".to_vec(),
    ] {
        assert_eq!(
            extractor.probe(&Artifact::from_bytes("cookies.txt", data.clone())),
            Probe::No
        );
        assert!(
            extractor
                .extract(&Artifact::from_bytes("cookies.txt", data))
                .is_err()
        );
    }
}

#[test]
fn racf_kdfaes_passphrase_extracts_the_records() {
    let extractor = extractor!("racf-kdfaes-passphrase");
    assert!(extractor.exact());
    assert!(matches!(
        extractor.probe(&artifact("racf-kdfaes-passphrase", "records.txt")),
        Probe::Yes(reason) if reason == "RACF KDFAES passphrase record"
    ));
    let hashes = extractor
        .extract(&artifact("racf-kdfaes-passphrase", "records.txt"))
        .expect("extract");
    let rendered = hashes
        .iter()
        .map(|hash| hash.render(&RenderOptions::default()).unwrap())
        .collect::<Vec<_>>()
        .join("\n");
    assert_eq!(rendered, expected("racf-kdfaes-passphrase", "records.hash"));
    assert!(hashes[0].modes().contains(&Mode::Hashcat(37500)));
}

#[test]
fn racf_kdfaes_passphrase_does_not_claim_password_records() {
    let extractor = extractor!("racf-kdfaes-passphrase");
    let password = b"$racf-kdfaes$*USER*E7D7E66D000180000008003200100010*00112233445566778899AABBCCDDEEFF*5390653DEC0316FB5AD56053208056A6";
    assert_eq!(
        extractor.probe(&Artifact::from_bytes("records.txt", password.to_vec())),
        Probe::No
    );
    assert_eq!(
        extractor.probe(&Artifact::from_bytes("records.txt", Vec::new())),
        Probe::No
    );
    let truncated = b"$racf-kdfaes$*USER*E7D7E66D000140000008003200100010*00*00";
    assert_eq!(
        extractor.probe(&Artifact::from_bytes("records.txt", truncated.to_vec())),
        Probe::No
    );
    assert!(
        extractor
            .extract(&Artifact::from_bytes("records.txt", truncated.to_vec()))
            .is_err()
    );
}

#[test]
fn sqlcipher_extracts_a_database_header() {
    let extractor = extractor!("sqlcipher");
    assert!(!extractor.exact());
    let artifact = with_members(
        "sqlcipher",
        "database.db",
        &[
            ("sqlcipher-type", "type.txt"),
            ("sqlcipher-iterations", "iterations.txt"),
        ],
    );
    assert!(matches!(
        extractor.probe(&artifact),
        Probe::Maybe(reason) if reason.contains("KDF parameters are external")
    ));
    let hashes = extractor.extract(&artifact).expect("extract");
    assert_eq!(hashes.len(), 1);
    assert_eq!(
        hashes[0].render(&RenderOptions::default()).unwrap(),
        expected("sqlcipher", "database.hash")
    );
    assert!(hashes[0].modes().contains(&Mode::Hashcat(24600)));
}

#[test]
fn sqlcipher_uses_an_explicit_preset() {
    let extractor = extractor!("sqlcipher");
    let artifact = with_members(
        "sqlcipher",
        "database.db",
        &[("sqlcipher-preset", "type.txt")],
    );
    let hashes = extractor.extract(&artifact).expect("extract");
    assert_eq!(
        hashes[0].render(&RenderOptions::default()).unwrap(),
        expected("sqlcipher", "database.hash")
    );
}

#[test]
fn sqlcipher_rejects_plain_sqlite_and_missing_parameters() {
    let extractor = extractor!("sqlcipher");
    let database = artifact("sqlcipher", "database.db");
    assert!(extractor.extract(&database).is_err());

    let mut plain = vec![0; 4096];
    plain[..16].copy_from_slice(b"SQLite format 3\0");
    assert_eq!(
        extractor.probe(&Artifact::from_bytes("plain.db", plain)),
        Probe::No
    );
    assert_eq!(
        extractor.probe(&Artifact::from_bytes("short.db", vec![0; 32])),
        Probe::No
    );
    assert_eq!(
        extractor.probe(&Artifact::from_bytes("odd.db", vec![0; 513])),
        Probe::No
    );
    assert_eq!(
        extractor.probe(&Artifact::from_bytes("empty.db", Vec::new())),
        Probe::No
    );
}
