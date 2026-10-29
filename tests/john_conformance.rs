//! John the Ripper conformance checks.
//!
//! Only named format labels are covered. Ad-hoc `dynamic=...` formats are out
//! of scope. These tests are ignored by default so the fast suite never needs
//! John.

mod common;

use std::process::Command;

use common::{VECTORS, reference, work_dir};

#[test]
#[ignore = "requires a John jumbo build"]
fn john_loads_every_vector() {
    let Some(john) = reference("OMNIEX_JOHN", "john") else {
        return;
    };
    let work = work_dir("john-conformance");
    let potfile = work.join("empty.pot");
    let _ = std::fs::remove_file(&potfile);
    let mut checked_formats = Vec::new();

    for vector in VECTORS {
        if vector.john.is_empty() {
            continue;
        }

        let hash_file = work.join(format!("{}.txt", vector.slug));
        std::fs::write(&hash_file, format!("{}\n", vector.hash)).expect("write hash file");

        for format in vector.john {
            if !checked_formats.contains(format) {
                let list = Command::new(&john)
                    .args(["--list=format-tests", &format!("--format={format}")])
                    .output()
                    .expect("run john --list=format-tests");
                assert!(
                    list.status.success() && !list.stdout.is_empty(),
                    "john does not know format `{format}`: {}",
                    String::from_utf8_lossy(&list.stderr)
                );
                checked_formats.push(*format);
            }

            let show = Command::new(&john)
                .args([
                    "--show",
                    &format!("--format={format}"),
                    &format!("--pot={}", potfile.display()),
                ])
                .arg(&hash_file)
                .output()
                .expect("run john --show");
            let output = format!(
                "{}{}",
                String::from_utf8_lossy(&show.stdout),
                String::from_utf8_lossy(&show.stderr)
            );

            assert!(
                show.status.success(),
                "john --show --format={format} failed for `{}`: {output}",
                vector.slug
            );
            assert!(
                output.contains("1 left") || output.contains("password hashes cracked"),
                "john --show --format={format} did not load `{}`: {output}",
                vector.slug
            );
            assert!(
                !output.contains("No password hashes loaded"),
                "john rejected `{}` as {format}: {output}",
                vector.slug
            );
        }
    }
}
