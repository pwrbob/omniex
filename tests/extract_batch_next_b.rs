//! IKEv1 aggressive-mode extraction tests.

#[path = "../src/extract/ike_john.rs"]
mod ike_john;
#[path = "../src/extract/ike_psk_md5.rs"]
mod ike_psk_md5;
#[path = "../src/extract/ike_psk_sha1.rs"]
mod ike_psk_sha1;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use omniex::extract::{Artifact, Extractor, Probe};
use omniex::{Mode, RenderOptions, Tool};

use ike_john::IkeJohnExtractor;
use ike_psk_md5::IkePskMd5Extractor;
use ike_psk_sha1::IkePskSha1Extractor;

static MD5: IkePskMd5Extractor = IkePskMd5Extractor;
static SHA1: IkePskSha1Extractor = IkePskSha1Extractor;
static JOHN: IkeJohnExtractor = IkeJohnExtractor;

fn fixture(kind: &str, name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/artifacts")
        .join(kind)
        .join(name)
}

fn artifact(kind: &str, name: &str) -> Artifact {
    Artifact::from_bytes(name, std::fs::read(fixture(kind, name)).unwrap())
}

fn expected(kind: &str, name: &str) -> String {
    std::fs::read_to_string(fixture(kind, name))
        .unwrap()
        .trim_end()
        .to_owned()
}

fn render(extractor: &dyn Extractor, artifact: &Artifact, tool: Tool) -> Vec<String> {
    extractor
        .extract(artifact)
        .expect("extract")
        .iter()
        .map(|value| {
            value
                .render(&RenderOptions {
                    tool,
                    ..RenderOptions::default()
                })
                .unwrap()
        })
        .collect()
}

fn hashes(extractor: &dyn Extractor, artifact: &Artifact) -> Vec<String> {
    render(extractor, artifact, Tool::Hashcat)
}

fn john_hashes(extractor: &dyn Extractor, artifact: &Artifact) -> Vec<String> {
    render(extractor, artifact, Tool::John)
}

#[test]
fn ike_extractors_match_their_fixtures() {
    assert_eq!(
        hashes(&MD5, &artifact("ike-psk-md5", "aggressive.pcap")),
        vec![expected("ike-psk-md5", "aggressive.hash")]
    );
    assert_eq!(
        hashes(&MD5, &artifact("ike-psk-md5", "aggressive.pcapng")),
        vec![expected("ike-psk-md5", "aggressive.hash")]
    );

    assert_eq!(
        hashes(&SHA1, &artifact("ike-psk-sha1", "aggressive.pcap")),
        vec![expected("ike-psk-sha1", "aggressive.hash")]
    );
    assert_eq!(
        hashes(&SHA1, &artifact("ike-psk-sha1", "aggressive.pcapng")),
        vec![expected("ike-psk-sha1", "aggressive.hash")]
    );

    assert_eq!(
        john_hashes(&JOHN, &artifact("ike-payload", "aggressive.pcap")),
        expected("ike-payload", "aggressive.john")
            .lines()
            .map(str::to_owned)
            .collect::<Vec<_>>()
    );
    assert_eq!(
        john_hashes(&JOHN, &artifact("ike-payload", "aggressive.pcapng")),
        expected("ike-payload", "aggressive.john")
            .lines()
            .map(str::to_owned)
            .collect::<Vec<_>>()
    );
}

#[test]
fn ike_extractors_scan_every_exchange() {
    let values: BTreeSet<String> = hashes(&MD5, &artifact("ike-psk-md5", "multi.pcap"))
        .into_iter()
        .collect();
    let wanted: BTreeSet<String> = expected("ike-psk-md5", "multi.hash")
        .lines()
        .map(str::to_owned)
        .collect();
    assert_eq!(values, wanted);

    let values: BTreeSet<String> = john_hashes(&JOHN, &artifact("ike-payload", "aggressive.pcap"))
        .into_iter()
        .collect();
    let wanted: BTreeSet<String> = expected("ike-payload", "aggressive.john")
        .lines()
        .map(str::to_owned)
        .collect();
    assert_eq!(values, wanted);
}

#[test]
fn ike_extractors_report_their_modes() {
    let values = MD5
        .extract(&artifact("ike-psk-md5", "aggressive.pcap"))
        .unwrap();
    assert!(values[0].modes().contains(&Mode::Hashcat(5300)));

    let values = SHA1
        .extract(&artifact("ike-psk-sha1", "aggressive.pcap"))
        .unwrap();
    assert!(values[0].modes().contains(&Mode::Hashcat(5400)));

    let values = JOHN
        .extract(&artifact("ike-payload", "aggressive.pcap"))
        .unwrap();
    assert!(values[0].modes().contains(&Mode::John("IKE")));
}

#[test]
fn ike_probes_require_structural_evidence() {
    for (extractor, kind, name) in [
        (&MD5 as &dyn Extractor, "ike-psk-md5", "aggressive.pcap"),
        (&MD5, "ike-psk-md5", "aggressive.pcapng"),
        (&SHA1, "ike-psk-sha1", "aggressive.pcap"),
        (&SHA1, "ike-psk-sha1", "aggressive.pcapng"),
    ] {
        assert!(
            matches!(extractor.probe(&artifact(kind, name)), Probe::Yes(_)),
            "{kind} {name}"
        );
    }

    // The John serialization is a rendering of the same exchange, so it is
    // only selected explicitly.
    for name in ["aggressive.pcap", "aggressive.pcapng"] {
        assert!(
            matches!(JOHN.probe(&artifact("ike-payload", name)), Probe::Maybe(_)),
            "ike-payload {name}"
        );
    }

    for (extractor, kind, name) in [
        (&MD5 as &dyn Extractor, "ike-psk-sha1", "aggressive.pcap"),
        (&SHA1, "ike-psk-md5", "aggressive.pcap"),
        (&MD5, "wpa-pmkid", "eapol.pcap"),
        (&SHA1, "wpa-pmkid", "eapol.pcap"),
        (&JOHN, "wpa-pmkid", "eapol.pcap"),
    ] {
        assert_eq!(
            extractor.probe(&artifact(kind, name)),
            Probe::No,
            "{kind} {name}"
        );
    }

    let text = Artifact::from_bytes("note.txt", b"not a capture".to_vec());
    for extractor in [&MD5 as &dyn Extractor, &SHA1, &JOHN] {
        assert_eq!(extractor.probe(&text), Probe::No);
        assert!(extractor.extract(&text).is_err());
    }
}

#[test]
fn truncated_captures_probe_maybe_and_fail_to_extract() {
    for (extractor, kind) in [
        (&MD5 as &dyn Extractor, "ike-psk-md5"),
        (&SHA1, "ike-psk-sha1"),
        (&JOHN, "ike-payload"),
    ] {
        let truncated = artifact(kind, "truncated.pcap");
        assert!(matches!(extractor.probe(&truncated), Probe::Maybe(_)));
        assert!(extractor.extract(&truncated).is_err());
    }
}

#[test]
fn empty_input_is_never_recognized() {
    let empty = Artifact::from_bytes("empty", Vec::new());
    for extractor in [&MD5 as &dyn Extractor, &SHA1, &JOHN] {
        assert_eq!(extractor.probe(&empty), Probe::No);
        assert!(extractor.extract(&empty).is_err());
    }
}

#[test]
fn ike_extractors_reject_the_wrong_digest_length() {
    assert!(
        MD5.extract(&artifact("ike-psk-sha1", "aggressive.pcap"))
            .is_err()
    );
    assert!(
        SHA1.extract(&artifact("ike-psk-md5", "aggressive.pcap"))
            .is_err()
    );
}
