//! Table-driven coverage checks that need no reference tools.

mod common;

use assert_cmd::Command;
use common::{VECTORS, vector_for, vector_modes};
use omniex::{Mode, ParseOptions, RenderOptions, Tool, registry};

#[test]
fn every_registered_type_has_a_vector() {
    for descriptor in registry::all() {
        assert!(
            vector_for(descriptor).is_some(),
            "no conformance vector for `{}`",
            descriptor.slug
        );
    }
}

#[test]
fn every_declared_mode_has_a_vector() {
    for descriptor in registry::all() {
        let vector = vector_for(descriptor).expect("vector exists");
        let covered = vector_modes(vector);

        for mode in descriptor.all_modes {
            assert!(
                covered.contains(mode),
                "mode {mode:?} for `{}` has no conformance vector",
                descriptor.slug
            );
        }
    }
}

#[test]
fn every_vector_names_a_registered_type() {
    for vector in VECTORS {
        assert!(
            registry::by_slug(vector.slug).is_some(),
            "vector `{}` does not name a registered type",
            vector.slug
        );
    }
}

#[test]
fn hashcat_vectors_round_trip_and_report_their_mode() {
    for vector in VECTORS {
        let descriptor = registry::by_slug(vector.slug).expect("registered");
        let opts = ParseOptions {
            tool: Tool::Hashcat,
            ..ParseOptions::default()
        };
        let render_opts = RenderOptions {
            tool: Tool::Hashcat,
            ..RenderOptions::default()
        };

        for entry in vector.hashcat {
            let value = registry::parse(descriptor, &entry.text(), &opts).unwrap_or_else(|error| {
                panic!(
                    "`{}` failed to parse the mode {} vector: {error}",
                    vector.slug, entry.mode
                )
            });

            let rendered = value
                .render(&render_opts)
                .unwrap_or_else(|error| panic!("`{}` failed to render: {error}", vector.slug));
            assert_eq!(
                rendered,
                entry.text(),
                "`{}` did not round-trip for hashcat mode {}",
                vector.slug,
                entry.mode
            );
            assert!(
                value.modes().contains(&Mode::Hashcat(entry.mode)),
                "`{}` parsed the mode {} vector but did not report that mode: {:?}",
                vector.slug,
                entry.mode,
                value.modes()
            );
        }
    }
}

#[test]
fn john_vectors_round_trip_and_report_their_format() {
    for vector in VECTORS {
        let descriptor = registry::by_slug(vector.slug).expect("registered");

        for entry in vector.john {
            let opts = ParseOptions {
                tool: Tool::John,
                ..ParseOptions::default()
            };
            let render_opts = RenderOptions {
                tool: Tool::John,
                ..RenderOptions::default()
            };

            let value = registry::parse(descriptor, entry.hash, &opts).unwrap_or_else(|error| {
                panic!(
                    "`{}` failed to parse the {} vector: {error}",
                    vector.slug, entry.format
                )
            });

            let rendered = value
                .render(&render_opts)
                .unwrap_or_else(|error| panic!("`{}` failed to render: {error}", vector.slug));
            assert_eq!(
                rendered, entry.hash,
                "`{}` did not round-trip for John format {}",
                vector.slug, entry.format
            );
            assert!(
                value.modes().contains(&Mode::John(entry.format)),
                "`{}` parsed the {} vector but did not report that format: {:?}",
                vector.slug,
                entry.format,
                value.modes()
            );
        }
    }
}

#[test]
fn vector_modes_are_a_subset_of_declared_modes() {
    for vector in VECTORS {
        let descriptor = registry::by_slug(vector.slug).expect("registered");

        for mode in vector_modes(vector) {
            assert!(
                descriptor.all_modes.contains(&mode),
                "`{}` vector names undeclared mode {mode:?}",
                vector.slug
            );
        }
    }
}

#[test]
fn modes_checklist_does_not_list_implemented_modes() {
    let mut section = "";
    for line in include_str!("../MODES.md").lines() {
        if line.starts_with("## ") {
            section = line;
        }
        if !matches!(
            section,
            "## hashcat modes" | "## John the Ripper formats" | "## hashcat bridged modes"
        ) {
            continue;
        }

        let Some(entry) = line.strip_prefix("- [ ] `") else {
            continue;
        };
        let Some((label, _)) = entry.split_once('`') else {
            continue;
        };

        for descriptor in registry::all() {
            let implemented = if section == "## John the Ripper formats" {
                descriptor.all_modes.contains(&Mode::John(label))
            } else {
                label
                    .parse::<u32>()
                    .is_ok_and(|number| descriptor.all_modes.contains(&Mode::Hashcat(number)))
            };
            assert!(
                !implemented,
                "`{label}` is implemented by `{}` but remains in MODES.md under {section}",
                descriptor.slug
            );
        }
    }
}

#[test]
fn readme_type_table_matches_the_types_command() {
    let output = Command::cargo_bin("omniex")
        .expect("binary is built")
        .env("COLUMNS", "1000")
        .arg("types")
        .output()
        .expect("types command runs");
    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout).expect("types output is UTF-8");
    let lines = stdout.lines().collect::<Vec<_>>();
    let header = lines
        .iter()
        .find(|line| line.starts_with("Slug"))
        .expect("types output has a header");
    let starts =
        ["Slug", "Name", "Hashcat", "John"].map(|name| header.find(name).expect("header column"));

    let cli_rows = lines
        .iter()
        .skip_while(|line| !line.starts_with("Slug"))
        .skip(1)
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            starts
                .iter()
                .enumerate()
                .map(|(index, start)| {
                    let end = starts.get(index + 1).copied().unwrap_or(line.len());
                    line[*start..end].trim().to_owned()
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();

    let readme_rows = include_str!("../README.md")
        .lines()
        .filter_map(|line| {
            let rest = line.strip_prefix("| `")?;
            let (slug, rest) = rest.split_once('`')?;
            let columns = rest.split('|').map(str::trim).collect::<Vec<_>>();
            if columns.len() < 5 {
                return None;
            }
            Some(vec![
                slug.to_owned(),
                columns[1].to_owned(),
                columns[2].to_owned(),
                columns[3].trim_matches('`').to_owned(),
            ])
        })
        .collect::<Vec<_>>();

    assert_eq!(
        readme_rows, cli_rows,
        "the README supported-type list must match `omniex types`"
    );
}

#[test]
fn readme_mode_badge_matches_the_registry_and_checklist() {
    let root = env!("CARGO_MANIFEST_DIR");
    let readme = std::fs::read_to_string(std::path::Path::new(root).join("README.md"))
        .expect("read README.md");
    let modes = std::fs::read_to_string(std::path::Path::new(root).join("MODES.md"))
        .expect("read MODES.md");

    let john_implemented: usize = registry::all()
        .iter()
        .map(|descriptor| {
            descriptor
                .all_modes
                .iter()
                .filter(|mode| matches!(mode, Mode::John(_)))
                .count()
        })
        .sum();
    let implemented: usize = registry::all()
        .iter()
        .map(|descriptor| descriptor.all_modes.len())
        .sum();
    let hashcat_implemented = implemented - john_implemented;

    let mut section = "";
    let mut hashcat_remaining = 0;
    let mut john_remaining = 0;
    for line in modes.lines() {
        if line.starts_with("## ") {
            section = line;
        }
        if !line.starts_with("- [ ] `") {
            continue;
        }
        match section {
            "## John the Ripper formats" => john_remaining += 1,
            "## hashcat modes" | "## hashcat bridged modes" => hashcat_remaining += 1,
            _ => {}
        }
    }

    let hashcat = format!(
        "hashcat_modes-{hashcat_implemented}%2F{}-",
        hashcat_implemented + hashcat_remaining
    );
    let john = format!(
        "John_modes-{john_implemented}%2F{}-",
        john_implemented + john_remaining
    );
    for badge in [hashcat, john] {
        assert!(
            readme.contains(&badge),
            "README must advertise `{badge}`; found no matching badge"
        );
    }
}
