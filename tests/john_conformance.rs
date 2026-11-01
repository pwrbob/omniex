//! John the Ripper conformance checks.
//!
//! Only named format labels are covered. Ad-hoc `dynamic=...` formats are out
//! of scope. These tests are ignored by default so the fast suite never needs
//! John.

mod common;

use std::path::Path;
use std::process::Command;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use common::{VECTORS, reference, selected_modes, work_dir};

struct WorkItem {
    slug: &'static str,
    format: &'static str,
    path: std::path::PathBuf,
}

#[test]
#[ignore = "requires a John jumbo build"]
fn john_loads_every_vector() {
    let Some(john) = reference("OMNIEX_JOHN", "john") else {
        return;
    };
    let work = work_dir("john-conformance");
    let selected = selected_modes();
    let subset = std::env::var("OMNIEX_CONFORMANCE_SUBSET").as_deref() == Ok("1");
    let mut items = Vec::new();

    for vector in VECTORS {
        let mut included = 0;
        for entry in vector.john {
            if let Some(labels) = &selected {
                if !labels.iter().any(|label| label == entry.format) {
                    continue;
                }
            }
            if subset && included > 0 {
                continue;
            }
            included += 1;

            let path = work.join(format!("{}-{}.txt", vector.slug, entry.format));
            std::fs::write(&path, format!("{}\n", entry.hash)).expect("write hash file");
            items.push(WorkItem {
                slug: vector.slug,
                format: entry.format,
                path,
            });
        }
    }

    run_parallel(&john, &items, worker_count(items.len()));
}

fn run_parallel(john: &Path, items: &[WorkItem], workers: usize) {
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
                    if let Err(message) = check_item(john, item) {
                        failures.lock().expect("failure list").push(message);
                    }
                }
            });
        }
    });

    let failures = failures.into_inner().expect("failure list");
    assert!(
        failures.is_empty(),
        "{} John conformance failure(s):\n{}",
        failures.len(),
        failures.join("\n")
    );
}

fn check_item(john: &Path, item: &WorkItem) -> Result<(), String> {
    let show = Command::new(john)
        .args(["--show=formats", &format!("--format={}", item.format)])
        .arg(&item.path)
        .output()
        .map_err(|error| format!("run john --show=formats: {error}"))?;
    let stdout = String::from_utf8_lossy(&show.stdout);
    let stderr = String::from_utf8_lossy(&show.stderr);

    if !show.status.success() {
        return Err(format!(
            "john --show=formats --format={} failed for `{}`: {stderr}",
            item.format, item.slug
        ));
    }

    let label = format!("\"label\":\"{}\"", item.format);
    if !stdout.contains(&label) {
        return Err(format!(
            "john did not load `{}` as {}: stdout={stdout} stderr={stderr}",
            item.slug, item.format
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
