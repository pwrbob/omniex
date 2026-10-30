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
    let mut items = Vec::new();
    let mut index = 0;

    for vector in VECTORS {
        let mut included = 0;
        for entry in vector.hashcat {
            if let Some(labels) = &selected
                && !labels.iter().any(|label| label == &entry.mode.to_string())
            {
                continue;
            }
            if subset && included > 0 {
                continue;
            }
            included += 1;

            let path = work.join(format!("{index}-{}-{}.txt", vector.slug, entry.mode));
            std::fs::write(&path, format!("{}\n", entry.hash)).expect("write hash file");
            items.push(WorkItem {
                slug: vector.slug,
                mode: entry.mode,
                path,
                session: format!("omniex-{index}"),
                identify: entry.identify,
            });
            index += 1;
        }
    }

    run_parallel(&hashcat, &potfile, &items, worker_count(items.len()));
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
            "hashcat --show -m {} failed for `{}`",
            item.mode, item.slug
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

    requested.min(items.max(1)).min(16)
}

fn identified_modes(stdout: &str) -> Vec<u32> {
    stdout
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .filter_map(|token| token.parse().ok())
        .collect()
}
