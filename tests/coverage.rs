//! Table-driven coverage checks that need no reference tools.

mod common;

use assert_cmd::Command;
use common::{VECTORS, vector_for, vector_modes};
use omniex::extract::EXTRACTORS;
use omniex::json::hash_document;
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
fn structured_hashes_are_recognized_by_one_type_only() {
    let opts = ParseOptions::default();
    let structured = [
        "mongodb-scram",
        "mongodb-scram-sha256",
        "mschapv2-naive",
        "nethalflm",
        "netlm",
        "netntlm-naive",
        "uuid-v3",
        "uuid-v5",
    ];
    let mut conflicts = Vec::new();
    for slug in structured {
        let vector = VECTORS
            .iter()
            .find(|vector| vector.slug == slug)
            .unwrap_or_else(|| panic!("no vector for `{slug}`"));
        for entry in vector
            .hashcat
            .iter()
            .map(|entry| entry.text())
            .chain(vector.john.iter().map(|entry| entry.text()))
        {
            let mut slugs: Vec<&str> = registry::all()
                .iter()
                .filter(|descriptor| registry::parse(descriptor, &entry, &opts).is_ok())
                .map(|descriptor| descriptor.slug)
                .collect();
            slugs.sort_unstable();
            if slugs != [slug] {
                conflicts.push(format!("{slug}: {slugs:?} <- {entry}"));
            }
        }
    }
    assert!(
        conflicts.is_empty(),
        "structured hashes must identify as one type:\n{}",
        conflicts.join("\n")
    );
}

#[test]
fn office_hashes_are_not_claimed_by_other_types() {
    let vector = VECTORS
        .iter()
        .find(|vector| vector.slug == "office")
        .expect("office vector");
    for entry in vector
        .hashcat
        .iter()
        .map(|entry| entry.text())
        .chain(vector.john.iter().map(|entry| entry.text()))
    {
        let mut slugs: Vec<&str> = registry::all()
            .iter()
            .filter(|descriptor| {
                registry::parse(descriptor, &entry, &ParseOptions::default()).is_ok()
            })
            .map(|descriptor| descriptor.slug)
            .collect();
        slugs.sort_unstable();
        assert_eq!(
            slugs,
            ["office"],
            "the office hash `{entry}` must only identify as office"
        );
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
fn every_vector_round_trips_through_a_json_hash_document() {
    for vector in VECTORS {
        let descriptor = registry::by_slug(vector.slug).expect("registered");

        let cases = vector
            .hashcat
            .iter()
            .map(|entry| (Tool::Hashcat, entry.text(), entry.mode.to_string()))
            .chain(
                vector
                    .john
                    .iter()
                    .map(|entry| (Tool::John, entry.text(), entry.format.to_owned())),
            );

        for (tool, original, label) in cases {
            let value = registry::parse(descriptor, &original, &ParseOptions::default())
                .unwrap_or_else(|error| {
                    panic!(
                        "`{}` failed to parse the {label} vector: {error}",
                        vector.slug
                    )
                });
            let document = hash_document(descriptor, value.as_ref());
            let text = serde_json::to_string(&document).expect("JSON document serializes");
            let again = (descriptor.parse_json)(&text).unwrap_or_else(|error| {
                panic!(
                    "`{}` failed to parse its JSON document: {error}",
                    vector.slug
                )
            });
            let rendered = again
                .render(&RenderOptions {
                    tool,
                    ..RenderOptions::default()
                })
                .unwrap_or_else(|error| {
                    panic!("`{}` failed to render from JSON: {error}", vector.slug)
                });
            assert_eq!(
                rendered, original,
                "`{}` did not round-trip through JSON for {label}",
                vector.slug
            );
        }
    }
}

#[test]
fn hashcat_vectors_round_trip_and_report_their_mode() {
    for vector in VECTORS {
        let descriptor = registry::by_slug(vector.slug).expect("registered");
        let opts = ParseOptions::default();
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
            let opts = ParseOptions::default();
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
fn changelog_matches_the_workspace_version() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let manifest = std::fs::read_to_string(root.join("Cargo.toml")).expect("read Cargo.toml");
    let changelog = std::fs::read_to_string(root.join("CHANGELOG.md")).expect("read CHANGELOG.md");

    let mut in_workspace = false;
    let mut version = None;
    for line in manifest.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_workspace = trimmed == "[workspace.package]";
            continue;
        }
        if in_workspace && let Some(rest) = trimmed.strip_prefix("version = ") {
            version = Some(rest.trim().trim_matches('"').to_owned());
            break;
        }
    }
    let version = version.expect("Cargo.toml must set the version under [workspace.package]");

    let first = changelog
        .lines()
        .filter_map(|line| line.strip_prefix("## ["))
        .filter_map(|line| line.split(']').next())
        .find(|entry| *entry != "Unreleased")
        .expect("CHANGELOG.md must list at least one release");

    assert_eq!(
        first, version,
        "the newest CHANGELOG.md entry must match the Cargo.toml version"
    );
}

#[test]
fn readme_artifact_table_matches_the_checklist() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let readme = std::fs::read_to_string(root.join("README.md")).expect("read README.md");
    let extraction =
        std::fs::read_to_string(root.join("EXTRACTION.md")).expect("read EXTRACTION.md");

    let mut expected: Vec<(String, usize)> = Vec::new();
    for line in extraction.lines() {
        if let Some(heading) = line.strip_prefix("## ") {
            expected.push((heading.trim().to_owned(), 0));
        } else if line.starts_with("- [x] ")
            && let Some((_, count)) = expected.last_mut()
        {
            *count += 1;
        }
    }
    expected.retain(|(_, count)| *count > 0);

    let table = readme
        .split("### Supported artifacts")
        .nth(1)
        .expect("README must document the supported artifact categories");
    let mut rows = Vec::new();
    let mut started = false;
    for line in table.lines() {
        if line.trim().is_empty() {
            if started {
                break;
            }
            continue;
        }
        let Some(rest) = line.strip_prefix("| ") else {
            if started {
                break;
            }
            continue;
        };
        started = true;
        let Some((name, count)) = rest.split_once(" | ") else {
            break;
        };
        let Ok(count) = count.trim().trim_end_matches('|').trim().parse::<usize>() else {
            continue;
        };
        rows.push((name.trim().to_owned(), count));
    }

    assert_eq!(
        rows, expected,
        "the README artifact table must match the categories in EXTRACTION.md"
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

// hashcat 8.0.0 mode entries and pinned John jumbo format labels.
const HASHCAT_MODES: usize = 720;
const JOHN_LABELS: usize = 265;

#[test]
fn readme_mode_badges_match_the_registry() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let readme = std::fs::read_to_string(root.join("README.md")).expect("read README.md");

    let mut hashcat = 0;
    let mut john = 0;
    for descriptor in registry::all() {
        for mode in descriptor.all_modes {
            match mode {
                Mode::Hashcat(_) => hashcat += 1,
                Mode::John(_) => john += 1,
            }
        }
    }

    assert_eq!(
        hashcat, HASHCAT_MODES,
        "the registry no longer covers every hashcat 8.0.0 mode; update the count and the README badge together"
    );
    assert_eq!(
        john, JOHN_LABELS,
        "the registry no longer covers every John jumbo label; update the count and the README badge together"
    );

    for badge in [
        format!("hashcat_modes-{hashcat}%2F{HASHCAT_MODES}-"),
        format!("John_modes-{john}%2F{JOHN_LABELS}-"),
    ] {
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
