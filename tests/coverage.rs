//! Table-driven coverage checks that need no reference tools.

mod common;

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
            let value = registry::parse(descriptor, entry.hash, &opts).unwrap_or_else(|error| {
                panic!(
                    "`{}` failed to parse the mode {} vector: {error}",
                    vector.slug, entry.mode
                )
            });

            assert_eq!(
                value.render(&render_opts).unwrap(),
                entry.hash,
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

            assert_eq!(
                value.render(&render_opts).unwrap(),
                entry.hash,
                "`{}` did not round-trip for John format {}",
                vector.slug,
                entry.format
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
fn readme_type_table_matches_the_registry() {
    let mut rows = 0;
    let mut in_table = false;
    for line in include_str!("../README.md").lines() {
        if line == "## Supported hash types" {
            in_table = true;
            continue;
        }
        if in_table && line.starts_with("A type is a logical hash type") {
            in_table = false;
        }
        if !in_table {
            continue;
        }
        let Some(rest) = line.strip_prefix("| `") else {
            continue;
        };
        let Some((slug, rest)) = rest.split_once('`') else {
            continue;
        };
        let columns = rest.split('|').map(str::trim).collect::<Vec<_>>();
        assert!(columns.len() >= 4, "malformed README row for `{slug}`");

        let descriptor =
            registry::by_slug(slug).unwrap_or_else(|| panic!("README lists unknown type `{slug}`"));
        let expected = {
            let (mut hashcat, mut john) = (Vec::new(), Vec::new());
            for mode in descriptor.all_modes {
                match mode {
                    Mode::Hashcat(number) => hashcat.push(number.to_string()),
                    Mode::John(label) => john.push((*label).to_owned()),
                }
            }
            let join = |values: Vec<String>| {
                if values.is_empty() {
                    "-".to_owned()
                } else {
                    values.join(", ")
                }
            };
            (join(hashcat), join(john))
        };

        assert_eq!(columns[1], expected.0, "README hashcat modes for `{slug}`");
        assert_eq!(
            columns[2].trim_matches('`'),
            expected.1,
            "README John formats for `{slug}`"
        );
        rows += 1;
    }

    assert_eq!(
        rows,
        registry::all().len(),
        "README lists {} types but {} are registered",
        rows,
        registry::all().len()
    );
}
