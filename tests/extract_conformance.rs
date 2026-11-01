//! Extractor conformance against the pinned John `*2john` scripts.
//!
//! These tests are ignored by default. CI runs them when the John build is
//! available. Extractors whose reference scripts produce a different
//! serialization, are broken under Python 3, or have no reference script are
//! covered by their fixture tests instead.

use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Clone, Copy)]
enum Normalize {
    Hash,
    Bks,
}

struct Case {
    name: &'static str,
    script: &'static str,
    args: &'static [&'static str],
    expected: &'static str,
    normalize: Normalize,
    subset: bool,
}

const CASES: &[Case] = &[
    Case {
        name: "ansible-vault",
        script: "ansible2john.py",
        args: &["tests/fixtures/artifacts/ansible/sample.yml"],
        expected: "tests/fixtures/artifacts/ansible/sample.hash",
        normalize: Normalize::Hash,
        subset: false,
    },
    Case {
        name: "bks-v1",
        script: "bks2john.py",
        args: &["tests/fixtures/artifacts/bks/empty-v1.bks"],
        expected: "tests/fixtures/artifacts/bks/empty-v1.hash",
        normalize: Normalize::Bks,
        subset: false,
    },
    Case {
        name: "bks-v2",
        script: "bks2john.py",
        args: &["tests/fixtures/artifacts/bks/empty-v2.bks"],
        expected: "tests/fixtures/artifacts/bks/empty-v2.hash",
        normalize: Normalize::Bks,
        subset: false,
    },
    Case {
        name: "dashlane-aes",
        script: "dashlane2john.py",
        args: &["tests/fixtures/artifacts/dashlane/sample.aes"],
        expected: "tests/fixtures/artifacts/dashlane/sample.aes.hash",
        normalize: Normalize::Hash,
        subset: false,
    },
    Case {
        name: "dashlane-archive",
        script: "dashlane2john.py",
        args: &["tests/fixtures/artifacts/dashlane/sample.dash"],
        expected: "tests/fixtures/artifacts/dashlane/sample.dash.hash",
        normalize: Normalize::Hash,
        subset: false,
    },
    Case {
        name: "ecryptfs-v2",
        script: "ecryptfs2john.py",
        args: &["tests/fixtures/artifacts/ecryptfs/wrapped-passphrase"],
        expected: "tests/fixtures/artifacts/ecryptfs/wrapped-passphrase.hash",
        normalize: Normalize::Hash,
        subset: false,
    },
    Case {
        name: "encfs",
        script: "encfs2john.py",
        args: &["tests/fixtures/artifacts/encfs"],
        expected: "tests/fixtures/artifacts/encfs/encfs.hash",
        normalize: Normalize::Hash,
        subset: false,
    },
    Case {
        name: "enpass",
        script: "enpass2john.py",
        args: &["tests/fixtures/artifacts/enpass/test.enpassdb"],
        expected: "tests/fixtures/artifacts/enpass/test.enpassdb.hash",
        normalize: Normalize::Hash,
        subset: false,
    },
    Case {
        name: "geli",
        script: "geli2john.py",
        args: &["tests/fixtures/artifacts/geli/sample.img"],
        expected: "tests/fixtures/artifacts/geli/sample.hash",
        normalize: Normalize::Hash,
        subset: false,
    },
    Case {
        name: "gpg",
        script: "gpg2john",
        args: &["tests/fixtures/artifacts/gpg/testkey1.key"],
        expected: "tests/fixtures/artifacts/gpg/testkey1.hash",
        normalize: Normalize::Hash,
        subset: true,
    },
    Case {
        name: "iwork",
        script: "iwork2john.py",
        args: &["tests/fixtures/artifacts/iwork/sample.key"],
        expected: "tests/fixtures/artifacts/iwork/sample.hash",
        normalize: Normalize::Hash,
        subset: false,
    },
    Case {
        name: "kwallet-legacy",
        script: "kwallet2john.py",
        args: &["tests/fixtures/artifacts/kwallet/legacy.kwl"],
        expected: "tests/fixtures/artifacts/kwallet/legacy.hash",
        normalize: Normalize::Hash,
        subset: false,
    },
    Case {
        name: "monero",
        script: "monero2john.py",
        args: &["tests/fixtures/artifacts/monero/wallet.keys"],
        expected: "tests/fixtures/artifacts/monero/wallet.hash",
        normalize: Normalize::Hash,
        subset: false,
    },
    Case {
        name: "odf",
        script: "libreoffice2john.py",
        args: &["tests/fixtures/artifacts/odf/sample.odt"],
        expected: "tests/fixtures/artifacts/odf/sample.hash",
        normalize: Normalize::Hash,
        subset: false,
    },
    Case {
        name: "pgpsda",
        script: "pgpsda2john.py",
        args: &["tests/fixtures/artifacts/pgpsda/sample.sda"],
        expected: "tests/fixtures/artifacts/pgpsda/sample.hash",
        normalize: Normalize::Hash,
        subset: false,
    },
    Case {
        name: "pwsafe",
        script: "pwsafe2john.py",
        args: &["tests/fixtures/artifacts/pwsafe-v3/sample.psafe3"],
        expected: "tests/fixtures/artifacts/pwsafe-v3/sample.john.hash",
        normalize: Normalize::Hash,
        subset: false,
    },
    Case {
        name: "softraid-pbkdf2",
        script: "openbsd_softraid2john.py",
        args: &["tests/fixtures/artifacts/openbsd-softraid/pbkdf2.img"],
        expected: "tests/fixtures/artifacts/openbsd-softraid/pbkdf2.hash",
        normalize: Normalize::Hash,
        subset: false,
    },
    Case {
        name: "softraid-bcrypt",
        script: "openbsd_softraid2john.py",
        args: &["tests/fixtures/artifacts/openbsd-softraid/bcrypt.img"],
        expected: "tests/fixtures/artifacts/openbsd-softraid/bcrypt.hash",
        normalize: Normalize::Hash,
        subset: false,
    },
];

fn script_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("OMNIEX_JOHN_RUN") {
        return PathBuf::from(dir);
    }
    let john = std::env::var_os("OMNIEX_JOHN").expect("OMNIEX_JOHN or OMNIEX_JOHN_RUN");
    Path::new(&john)
        .parent()
        .expect("John run directory")
        .to_path_buf()
}

fn run(script: &Path, args: &[&str], name: &str) -> String {
    let mut command = if script.extension().is_some_and(|ext| ext == "py") {
        let mut command = Command::new("python3");
        command.arg(script);
        command
    } else {
        Command::new(script)
    };
    let output = command
        .args(args)
        .output()
        .unwrap_or_else(|error| panic!("run {name} reference: {error}"));
    assert!(
        output.status.success(),
        "{name} reference failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("reference stdout is UTF-8")
}

fn normalize(stdout: &str, mode: Normalize) -> Vec<String> {
    stdout
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            let start = line.find('$')?;
            let mut hash = &line[start..];
            if let Some(index) = hash.find(":::") {
                hash = &hash[..index];
            }
            Some(match mode {
                Normalize::Hash => hash.to_owned(),
                Normalize::Bks => hash.replace("b'", "").replace('\'', ""),
            })
        })
        .collect()
}

fn expected(path: &str) -> Vec<String> {
    std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("read {path}: {error}"))
        .lines()
        .map(str::to_owned)
        .collect()
}

#[test]
#[ignore = "requires the pinned John extractor scripts"]
fn extractors_match_john_reference_output() {
    let dir = script_dir();
    for case in CASES {
        let script = dir.join(case.script);
        assert!(
            script.exists(),
            "missing reference script {}",
            script.display()
        );
        let got = normalize(&run(&script, case.args, case.name), case.normalize);
        let want = expected(case.expected);
        if case.subset {
            assert!(
                got.iter().all(|hash| want.contains(hash)),
                "{} reference output is not a subset of the fixture\nreference: {got:?}\nfixture: {want:?}",
                case.name
            );
        } else {
            assert_eq!(got, want, "{} reference output differs", case.name);
        }
    }
}
