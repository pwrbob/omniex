//! Table-driven coverage checks that need no reference tools.

mod common;

use assert_cmd::Command;
use common::{VECTORS, vector_for, vector_modes};
use omniex::extract::EXTRACTORS;
use omniex::{Mode, ParseOptions, RenderOptions, Tool, registry};

#[test]
fn slugs_and_names_do_not_name_the_cracker() {
    for descriptor in registry::all() {
        for label in [descriptor.slug, descriptor.name] {
            let lowered = label.to_ascii_lowercase();
            let tool_named = lowered.contains("john")
                || lowered.contains("-opencl")
                || lowered.contains("hashcat");
            assert!(
                !tool_named,
                "`{label}` names the target tool; describe the algorithm or format instead"
            );
        }
    }
}

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

            let value = registry::parse(descriptor, &entry.text(), &opts).unwrap_or_else(|error| {
                panic!(
                    "`{}` failed to parse the {} vector: {error}",
                    vector.slug, entry.format
                )
            });

            let rendered = value
                .render(&render_opts)
                .unwrap_or_else(|error| panic!("`{}` failed to render: {error}", vector.slug));
            assert_eq!(
                rendered,
                entry.text(),
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
fn readme_exact_extractor_badge_matches_the_registry() {
    let root = env!("CARGO_MANIFEST_DIR");
    let readme = std::fs::read_to_string(std::path::Path::new(root).join("README.md"))
        .expect("read README.md");

    let exact = EXTRACTORS
        .iter()
        .filter(|extractor| extractor.exact())
        .count();
    let expected = format!("exact_extractors-{exact}%2F{}-", EXTRACTORS.len());
    assert!(
        readme.contains(&expected),
        "README must advertise `{expected}`; found no matching badge"
    );
}

#[test]
fn readme_extraction_badge_matches_the_checklist() {
    let root = env!("CARGO_MANIFEST_DIR");
    let readme = std::fs::read_to_string(std::path::Path::new(root).join("README.md"))
        .expect("read README.md");
    let extraction = std::fs::read_to_string(std::path::Path::new(root).join("EXTRACTION.md"))
        .expect("read EXTRACTION.md");

    let done = extraction
        .lines()
        .filter(|line| line.starts_with("- [x] "))
        .count();
    let remaining = extraction
        .lines()
        .filter(|line| line.starts_with("- [ ] "))
        .count();
    let expected = format!("extractor_formats-{done}%2F{}-", done + remaining);
    assert!(
        readme.contains(&expected),
        "README must advertise `{expected}`; found no matching badge"
    );
}

#[test]
fn readme_external_sample_badge_matches_the_runner() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let base = root.join("scripts/external-samples");
    let mut formats = std::collections::BTreeSet::new();

    for entry in std::fs::read_dir(base.join("repos")).expect("read external sample repos") {
        let path = entry.expect("repo entry").path().join("manifest.toml");
        if !path.is_file() {
            continue;
        }
        let text = std::fs::read_to_string(&path).expect("read manifest");
        let manifest: toml::Value = toml::from_str(&text).expect("parse manifest");
        if manifest.get("id").and_then(toml::Value::as_str) == Some("omniex-fixtures") {
            continue;
        }
        for case in manifest
            .get("case")
            .and_then(toml::Value::as_array)
            .into_iter()
            .flatten()
        {
            if let Some(slug) = case.get("slug").and_then(toml::Value::as_str) {
                formats.insert(slug.to_owned());
            }
        }
    }

    let mut cases = 0;
    for entry in std::fs::read_dir(base.join("locks")).expect("read external sample locks") {
        let path = entry.expect("lock entry").path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("toml") {
            continue;
        }
        let text = std::fs::read_to_string(&path).expect("read lock");
        let lock: toml::Value = toml::from_str(&text).expect("parse lock");
        cases += lock
            .get("file")
            .and_then(toml::Value::as_array)
            .map_or(0, Vec::len);
    }

    let readme = std::fs::read_to_string(root.join("README.md")).expect("read README.md");
    let expected = format!(
        "external_samples-{}_formats_%2F_{}_cases-",
        formats.len(),
        cases
    );
    assert!(
        readme.contains(&expected),
        "README must advertise `{expected}`; found no matching badge"
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

#[test]
fn opencl_only_john_vectors_are_parse_render_only() {
    for vector in VECTORS {
        for entry in vector.john {
            if entry.format.to_ascii_lowercase().contains("opencl") {
                assert!(
                    !entry.conformance,
                    "`{}` must not invoke John's OpenCL backend for `{}`",
                    vector.slug, entry.format
                );
            }
        }
    }
}

#[test]
fn external_sample_john_cases_are_renderable_as_john() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let base = root.join("scripts/external-samples").join("repos");

    for entry in std::fs::read_dir(base).expect("read external sample repos") {
        let path = entry.expect("repo entry").path().join("manifest.toml");
        if !path.is_file() {
            continue;
        }
        let text = std::fs::read_to_string(&path).expect("read manifest");
        let manifest: toml::Value = toml::from_str(&text).expect("parse manifest");
        for case in manifest
            .get("case")
            .and_then(toml::Value::as_array)
            .into_iter()
            .flatten()
        {
            let reference = case
                .get("reference")
                .and_then(toml::Value::as_str)
                .unwrap_or("");
            let format = case
                .get("format")
                .and_then(toml::Value::as_str)
                .unwrap_or_else(|| {
                    if reference.starts_with("john:") {
                        "john"
                    } else {
                        "hashcat"
                    }
                });
            if format != "john" {
                continue;
            }
            let slug = case
                .get("slug")
                .and_then(toml::Value::as_str)
                .expect("case slug");
            let descriptor = registry::by_slug(slug)
                .unwrap_or_else(|| panic!("`{slug}` is not a registered hash type"));
            assert!(
                descriptor
                    .all_modes
                    .iter()
                    .any(|mode| matches!(mode, Mode::John(_))),
                "external sample case `{}` extracts `{slug}` as John, but the type declares no John format",
                case.get("name")
                    .and_then(toml::Value::as_str)
                    .unwrap_or(slug)
            );
        }
    }
}
