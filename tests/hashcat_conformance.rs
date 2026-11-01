//! Hashcat conformance checks.
//!
//! These tests are ignored by default so the fast suite never needs hashcat.
//! CI runs them with `--ignored` against a pinned hashcat build.

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use common::{VECTORS, reference, selected_modes, work_dir};

struct WorkItem {
    slug: &'static str,
    mode: u32,
    path: PathBuf,
    session: String,
    identify: bool,
}

#[test]
#[ignore = "requires a hashcat build"]
fn hashcat_identifies_and_loads_every_vector() {
    let Some(hashcat) = reference("OMNIEX_HASHCAT", "hashcat") else {
        return;
    };
    let work = work_dir("hashcat-conformance");
    let potfile = work.join("empty.pot");
    let _ = std::fs::remove_file(&potfile);
    let selected = selected_modes();
    let subset = std::env::var("OMNIEX_CONFORMANCE_SUBSET").as_deref() == Ok("1");
    let shard = std::env::var("OMNIEX_CONFORMANCE_SHARD")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    let shards = std::env::var("OMNIEX_CONFORMANCE_SHARDS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|count| *count > 0)
        .unwrap_or(1);
    let selected_entries = select_vectors(selected.as_deref(), subset, shard, shards);
    let mut items = Vec::with_capacity(selected_entries.len());

    for (index, slug, entry) in selected_entries {
        let path = work.join(format!("{index}-{slug}-{}.txt", entry.mode));
        if entry.binary {
            std::fs::write(&path, decode_hex(&entry.text())).expect("write binary hash file");
        } else {
            std::fs::write(&path, format!("{}\n", entry.text())).expect("write hash file");
        }
        items.push(WorkItem {
            slug,
            mode: entry.mode,
            path,
            session: format!("omniex-{}-{index}", std::process::id()),
            identify: entry.identify,
        });
    }

    run_parallel(&hashcat, &potfile, &items, worker_count(items.len()));
}

fn select_vectors(
    selected: Option<&[String]>,
    subset: bool,
    shard: usize,
    shards: usize,
) -> Vec<(usize, &'static str, &'static common::HashcatVector)> {
    assert!(
        shards > 0,
        "OMNIEX_CONFORMANCE_SHARDS must be greater than zero"
    );
    assert!(
        shard < shards,
        "OMNIEX_CONFORMANCE_SHARD must be less than OMNIEX_CONFORMANCE_SHARDS"
    );

    let mut selected_entries = Vec::new();
    let mut ordinal = 0;

    for vector in VECTORS {
        let mut included = 0;
        for entry in vector.hashcat {
            if let Some(labels) = selected
                && !labels.iter().any(|label| label == &entry.mode.to_string())
            {
                continue;
            }

            let current = ordinal;
            ordinal += 1;
            if subset && included > 0 {
                continue;
            }
            included += 1;
            if current % shards == shard {
                selected_entries.push((current, vector.slug, entry));
            }
        }
    }

    selected_entries
}

#[test]
fn shard_selection_partitions_every_vector() {
    const SHARDS: usize = 4;

    for subset in [false, true] {
        let all = select_vectors(None, subset, 0, 1);
        let expected = all.iter().map(|(index, _, _)| *index).collect::<Vec<_>>();
        let mut seen = Vec::new();

        for shard in 0..SHARDS {
            let entries = select_vectors(None, subset, shard, SHARDS);
            assert!(
                !entries.is_empty(),
                "shard {shard} is empty (subset={subset})"
            );
            seen.extend(entries.iter().map(|(index, _, _)| *index));
        }

        seen.sort_unstable();
        assert_eq!(
            seen, expected,
            "shards must partition the full vector set without gaps or overlaps"
        );
    }
}

fn run_parallel(hashcat: &Path, potfile: &Path, items: &[WorkItem], workers: usize) {
    let next = AtomicUsize::new(0);
    let failures = Mutex::new(Vec::new());

    std::thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| {
                loop {
                    let index = next.fetch_add(1, Ordering::Relaxed);
                    let Some(item) = items.get(index) else {
                        break;
                    };
                    if let Err(message) = check_item(hashcat, potfile, item) {
                        failures.lock().expect("failure list").push(message);
                    }
                }
            });
        }
    });

    let failures = failures.into_inner().expect("failure list");
    assert!(
        failures.is_empty(),
        "{} hashcat conformance failure(s):\n{}",
        failures.len(),
        failures.join("\n")
    );
}

fn check_item(hashcat: &Path, potfile: &Path, item: &WorkItem) -> Result<(), String> {
    if item.identify {
        let identify = Command::new(hashcat)
            .args(["--session", &item.session, "--identify"])
            .arg(&item.path)
            .output()
            .map_err(|error| format!("run hashcat --identify: {error}"))?;
        if !identify.status.success() {
            return Err(format!(
                "hashcat --identify failed for `{}` mode {}: {}",
                item.slug,
                item.mode,
                String::from_utf8_lossy(&identify.stderr)
            ));
        }

        let modes = identified_modes(&String::from_utf8_lossy(&identify.stdout));
        if !modes.contains(&item.mode) {
            return Err(format!(
                "hashcat did not identify mode {} for `{}` (saw {modes:?})",
                item.mode, item.slug
            ));
        }
    }

    let show = Command::new(hashcat)
        .args([
            "--session",
            &item.session,
            "--show",
            "-m",
            &item.mode.to_string(),
            "--potfile-path",
        ])
        .arg(potfile)
        .arg(&item.path)
        .output()
        .map_err(|error| format!("run hashcat --show: {error}"))?;
    if !show.status.success() {
        return Err(format!(
            "hashcat --show -m {} failed for `{}`: {}",
            item.mode,
            item.slug,
            String::from_utf8_lossy(&show.stderr)
        ));
    }

    let output = format!(
        "{}{}",
        String::from_utf8_lossy(&show.stdout),
        String::from_utf8_lossy(&show.stderr)
    );
    if output.contains("No hashes loaded") {
        return Err(format!(
            "hashcat --show -m {} rejected `{}`: {output}",
            item.mode, item.slug
        ));
    }

    Ok(())
}

fn worker_count(items: usize) -> usize {
    let requested = std::env::var("OMNIEX_CONFORMANCE_WORKERS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|workers| *workers > 0)
        .unwrap_or_else(|| {
            std::thread::available_parallelism()
                .map(usize::from)
                .unwrap_or(1)
        });

    requested.min(items.max(1)).min(32)
}

fn decode_hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digit = |byte: u8| match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                b'A'..=b'F' => byte - b'A' + 10,
                _ => panic!("invalid hex digit"),
            };
            (digit(pair[0]) << 4) | digit(pair[1])
        })
        .collect()
}

fn identified_modes(stdout: &str) -> Vec<u32> {
    stdout
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .filter_map(|token| token.parse().ok())
        .collect()
}
