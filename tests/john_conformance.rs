//! John the Ripper conformance checks.
//!
//! Only named format labels are covered. Ad-hoc `dynamic=...` formats are out
//! of scope. These tests are ignored by default so the fast suite never needs
//! John.

mod common;

use std::process::Command;

use common::{VECTORS, reference, selected_modes, work_dir};

#[test]
#[ignore = "requires a John jumbo build"]
fn john_loads_every_vector() {
    let Some(john) = reference("OMNIEX_JOHN", "john") else {
        return;
    };
    let work = work_dir("john-conformance");
    let mut checked_formats = Vec::new();
    let selected = selected_modes();
    let subset = std::env::var("OMNIEX_CONFORMANCE_SUBSET").as_deref() == Ok("1");

    for vector in VECTORS {
        let mut included = 0;
        for entry in vector.john {
            if let Some(labels) = &selected
                && !labels.iter().any(|label| label == entry.format)
            {
                continue;
            }
            if subset && included > 0 {
                continue;
            }
            included += 1;

            let hash_file = work.join(format!("{}-{}.txt", vector.slug, entry.format));
            std::fs::write(&hash_file, format!("{}\n", entry.hash)).expect("write hash file");

            if !checked_formats.contains(&entry.format) {
                let list = Command::new(&john)
                    .args(["--list=format-tests", &format!("--format={}", entry.format)])
                    .output()
                    .expect("run john --list=format-tests");
                assert!(
                    list.status.success() && !list.stdout.is_empty(),
                    "john does not know format `{}`: {}",
                    entry.format,
                    String::from_utf8_lossy(&list.stderr)
                );
                checked_formats.push(entry.format);
            }

            let show = Command::new(&john)
                .args(["--show=formats", &format!("--format={}", entry.format)])
                .arg(&hash_file)
                .output()
                .expect("run john --show=formats");
            let stdout = String::from_utf8_lossy(&show.stdout);
            let stderr = String::from_utf8_lossy(&show.stderr);
            let label = format!("\"label\":\"{}\"", entry.format);

            assert!(
                show.status.success(),
                "john --show=formats --format={} failed for `{}`: {stderr}",
                entry.format,
                vector.slug
            );
            assert!(
                stdout.contains(&label),
                "john did not load `{}` as {}: stdout={stdout} stderr={stderr}",
                vector.slug,
                entry.format
            );
        }
    }
}
