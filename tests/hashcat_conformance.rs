//! Hashcat conformance checks.
//!
//! These tests are ignored by default so the fast suite never needs hashcat.
//! CI runs them with `--ignored` against a pinned hashcat build.

mod common;

use std::process::Command;

use common::{VECTORS, reference, work_dir};

#[test]
#[ignore = "requires a hashcat build"]
fn hashcat_identifies_and_loads_every_vector() {
    let Some(hashcat) = reference("OMNIEX_HASHCAT", "hashcat") else {
        return;
    };
    let work = work_dir("hashcat-conformance");
    let potfile = work.join("empty.pot");
    let _ = std::fs::remove_file(&potfile);

    for vector in VECTORS {
        if vector.hashcat.is_empty() {
            continue;
        }

        let hash_file = work.join(format!("{}.txt", vector.slug));
        std::fs::write(&hash_file, format!("{}\n", vector.hash)).expect("write hash file");

        let identify = Command::new(&hashcat)
            .arg("--identify")
            .arg(&hash_file)
            .output()
            .expect("run hashcat --identify");
        assert!(
            identify.status.success(),
            "hashcat --identify failed for `{}`: {}",
            vector.slug,
            String::from_utf8_lossy(&identify.stderr)
        );

        let modes = identified_modes(&String::from_utf8_lossy(&identify.stdout));
        for mode in vector.hashcat {
            assert!(
                modes.contains(mode),
                "hashcat did not identify mode {mode} for `{}` (saw {modes:?})",
                vector.slug
            );
        }

        for mode in vector.hashcat {
            let show = Command::new(&hashcat)
                .args(["--show", "-m", &mode.to_string(), "--potfile-path"])
                .arg(&potfile)
                .arg(&hash_file)
                .output()
                .expect("run hashcat --show");
            assert!(
                show.status.success(),
                "hashcat --show -m {mode} failed for `{}`",
                vector.slug
            );

            let output = format!(
                "{}{}",
                String::from_utf8_lossy(&show.stdout),
                String::from_utf8_lossy(&show.stderr)
            );
            assert!(
                !output.contains("No hashes loaded"),
                "hashcat --show -m {mode} rejected `{}`: {output}",
                vector.slug
            );
        }
    }
}

fn identified_modes(stdout: &str) -> Vec<u32> {
    stdout
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .filter_map(|token| token.parse().ok())
        .collect()
}
