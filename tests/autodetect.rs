//! Auto-detection over every committed artifact fixture.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use omniex::extract::{self, Artifact, Selection};

/// Fixtures whose artifact is described by more than one hash type.
///
/// These carry overlapping signatures, so auto-detection reports the
/// candidates instead of picking one. The test still requires the expected
/// extractor to be among them.
const TOLERATED: &[&str] = &[
    "aix-smd5/passwd",
    "apple-dmg/aes.dmg",
    "as400-des/dump.txt",
    "as400-des/profile.bin",
    "blockchain-second/wallet.json",
    "dashlane/sample.aes",
    "iscsi-chap/login.pcap",
    "jks-private-key/keystore.jks",
    "krb5db-old/dsinternals.txt",
    "krb5db-old/mimikatz.txt",
    "krb5db17/mimikatz.txt",
    "krb5db18/mimikatz.txt",
    "lotus-notes/user.id",
    "keplr/keyring.json",
    "keystore/keystore-12345678.jks",
    "keystore/keystore-password123.jks",
    "ldap-sha1/sample.ldif",
    "md5crypt/shadow",
    "multibit/classic.key",
    "mssql-2012/dump.sql",
    "onepassword-agile/encryptionKeys.js",
    "onepassword-cloud/profile.js",
    "openssl-enc/secret-b64.enc",
    "pkcs12/bundle-sha1.p12",
    "pkcs12/bundle-sha256.p12",
    "pkcs12/bundle.p12",
    "pem-private-key/key-sha256.pem",
    "pwsafe-v3/sample.psafe3",
    "racf-kdfaes-passphrase/records.txt",
    "racf/CRACF.TXT",
    "vdi/sample.vbox",
    "vmware-vmx/sample.vmx",
    "vmx-keysafe/sample.vmx",
    "wpa-pmkid/pmkid.pcap",
    "wpa-pmkid-legacy/pmkid.pcap",
];

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/artifacts")
}

fn companions(case: &toml::Value) -> BTreeMap<String, String> {
    case.get("companions")
        .and_then(toml::Value::as_table)
        .map(|table| {
            table
                .iter()
                .filter_map(|(role, file)| Some((role.clone(), file.as_str()?.to_owned())))
                .collect()
        })
        .unwrap_or_default()
}

fn cases(manifest: &toml::Value) -> Vec<toml::Value> {
    manifest
        .get("case")
        .and_then(toml::Value::as_array)
        .cloned()
        .unwrap_or_else(|| vec![manifest.clone()])
}

/// Manifest cases, or every plausible artifact in a directory without them.
fn fixture_cases(directory: &Path, manifest: &toml::Value) -> Vec<Option<(String, Artifact)>> {
    let cases = cases(manifest);
    if cases
        .iter()
        .any(|case| case.get("artifact").and_then(toml::Value::as_str).is_some())
    {
        return cases.iter().map(|case| artifact(directory, case)).collect();
    }

    let Ok(entries) = std::fs::read_dir(directory) else {
        return Vec::new();
    };
    let mut files = entries
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|file| {
            !file.ends_with(".hash")
                && !file.ends_with(".toml")
                && !file.ends_with(".sh")
                && !file.ends_with(".py")
                && !file.ends_with(".md")
                && file != "manifest.toml"
        })
        .collect::<Vec<_>>();
    files.sort();
    files
        .into_iter()
        .map(|file| {
            let artifact = Artifact::from_file(&directory.join(&file)).ok()?;
            Some((file, artifact))
        })
        .collect()
}

fn artifact(directory: &Path, case: &toml::Value) -> Option<(String, Artifact)> {
    let name = case.get("artifact").and_then(toml::Value::as_str)?;
    let mut artifact = Artifact::from_file(&directory.join(name)).ok()?;
    for (role, file) in companions(case) {
        let source = extract::FileSource::open(&directory.join(file)).ok()?;
        artifact = artifact.with_member(role, source);
    }
    Some((name.to_owned(), artifact))
}

#[test]
fn every_supported_fixture_auto_detects() {
    let mut directories = std::fs::read_dir(fixtures())
        .expect("read fixtures")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .collect::<Vec<_>>();
    directories.sort();

    let mut unique = 0;
    let mut tolerated = 0;
    let mut skipped = Vec::new();
    let mut failures = Vec::new();

    for directory in directories {
        let dir_name = directory
            .file_name()
            .and_then(|name| name.to_str())
            .expect("fixture directory name");
        let Ok(text) = std::fs::read_to_string(directory.join("manifest.toml")) else {
            continue;
        };
        let manifest: toml::Value = toml::from_str(&text).expect("parse fixture manifest");
        let manifest_type = manifest.get("type").and_then(toml::Value::as_str);
        let extractor = manifest_type
            .and_then(extract::by_slug)
            .or_else(|| extract::by_slug(dir_name));
        let Some(extractor) = extractor else {
            skipped.push(format!("{dir_name} (no extractor)"));
            continue;
        };
        let slug = extractor.slug();

        for case in fixture_cases(&directory, &manifest) {
            let Some((name, artifact)) = case else {
                continue;
            };
            let label = format!("{slug}/{name}");
            let selection = extract::select(extract::EXTRACTORS, &artifact);

            if !extractor.exact() {
                if let Selection::Unique(found) = selection
                    && found.slug() == slug
                {
                    failures.push(format!("{label}: {slug} is Maybe-only but auto-detected"));
                }
                skipped.push(label);
                continue;
            }

            if extractor.extract(&artifact).is_err() {
                skipped.push(label);
                continue;
            }

            match selection {
                Selection::Unique(found) if found.slug() == slug => unique += 1,
                Selection::Unique(found) => failures.push(format!(
                    "{label}: selected {} instead of {slug}",
                    found.slug()
                )),
                Selection::Ambiguous(candidates) | Selection::Unconfirmed(candidates) => {
                    let tolerated_here = TOLERATED.contains(&label.as_str());
                    let listed = candidates
                        .iter()
                        .any(|candidate| candidate.extractor.slug() == slug);
                    if !tolerated_here {
                        failures.push(format!(
                            "{label}: not unique [{}]",
                            candidates
                                .iter()
                                .map(|candidate| candidate.extractor.slug())
                                .collect::<Vec<_>>()
                                .join(", ")
                        ));
                    } else if !listed {
                        failures.push(format!("{label}: {slug} missing from candidates"));
                    } else {
                        tolerated += 1;
                    }
                }
                Selection::Unsupported(candidate) => failures.push(format!(
                    "{label}: reported unsupported ({}) instead of {slug}",
                    candidate.extractor.slug()
                )),
                Selection::None => failures.push(format!("{label}: no candidate")),
            }
        }
    }

    eprintln!(
        "auto-detected {unique}, tolerated {tolerated}, skipped {}, failures {}",
        skipped.len(),
        failures.len()
    );
    for failure in &failures {
        eprintln!("  {failure}");
    }
    assert!(
        failures.is_empty(),
        "{} fixtures did not auto-detect",
        failures.len()
    );
    assert!(unique > 150, "too few fixtures auto-detected: {unique}");
}

#[test]
fn auto_detection_reads_a_bounded_amount() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    use omniex::extract::ReadAt;

    struct CountingSource {
        data: Arc<Vec<u8>>,
        reads: Arc<AtomicU64>,
    }

    impl ReadAt for CountingSource {
        fn len(&self) -> u64 {
            self.data.len() as u64
        }

        fn read_at(&self, offset: u64, out: &mut [u8]) -> std::io::Result<usize> {
            self.reads.fetch_add(out.len() as u64, Ordering::Relaxed);
            let offset = usize::try_from(offset).unwrap_or(usize::MAX);
            let Some(rest) = self.data.get(offset..) else {
                return Ok(0);
            };
            let read = rest.len().min(out.len());
            out[..read].copy_from_slice(&rest[..read]);
            Ok(read)
        }
    }

    let reads = Arc::new(AtomicU64::new(0));
    let artifact = Artifact::new(
        "junk",
        CountingSource {
            data: Arc::new(vec![0u8; 64 * 1024 * 1024]),
            reads: Arc::clone(&reads),
        },
    );
    let _ = extract::select(extract::EXTRACTORS, &artifact);
    let total = reads.load(Ordering::Relaxed);
    eprintln!("auto-detection read {total} bytes");
    assert!(
        total < 32 * 1024 * 1024,
        "auto-detection read {total} bytes from a 64 MiB artifact"
    );
}
