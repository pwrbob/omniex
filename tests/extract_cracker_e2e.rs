//! End-to-end checks from artifact extraction to cracker parsing.
//!
//! These tests are ignored by default because they require the pinned hashcat
//! and John builds. They extract hashes from the artifact fixtures, compare
//! them with the fixture's declared serialization, then ask each cracker to
//! load the extracted value without running an attack.
//!
//! A fixture opts in by declaring `hashcat = "..."` or `john = "..."` in its
//! `manifest.toml`. A value of `-` means that tool is not supported. Multiple
//! artifacts for one type use repeated `[[case]]` tables:
//!
//! ```toml
//! type = "sqlcipher"
//!
//! [[case]]
//! artifact = "database.db"
//! companions = { "sqlcipher-type" = "type.txt", "sqlcipher-iterations" = "iterations.txt" }
//! hashcat = "SQLCIPHER*..."
//! john = "-"
//!
//! [[case]]
//! artifact = "database-other.db"
//! hashcat = "SQLCIPHER*..."
//! ```

mod common;

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use common::{reference, selected_modes, work_dir};
use omniex::extract::{Artifact, MemorySource, by_slug};
use omniex::{HashTypeDescriptor, Mode, RenderOptions, Tool, registry};
use toml::Value;

struct Case {
    descriptor: &'static HashTypeDescriptor,
    artifact: PathBuf,
    companions: Vec<(String, PathBuf)>,
    hashcat: Option<Vec<String>>,
    john: Option<Vec<String>>,
}

fn resolve(base: &Path, value: &str) -> PathBuf {
    base.join(value)
}

fn string_field(case: &Value, root: &Value, key: &str) -> Option<String> {
    case.get(key)
        .or_else(|| root.get(key))
        .and_then(Value::as_str)
        .map(str::to_owned)
}

fn hash_field(case: &Value, root: &Value, key: &str) -> Option<Vec<String>> {
    let value = case.get(key).or_else(|| root.get(key))?;
    let hashes = match value {
        Value::String(value) => value
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && *line != "-")
            .map(str::to_owned)
            .collect::<Vec<_>>(),
        Value::Array(values) => values
            .iter()
            .filter_map(Value::as_str)
            .flat_map(str::lines)
            .map(str::trim)
            .filter(|line| !line.is_empty() && *line != "-")
            .map(str::to_owned)
            .collect::<Vec<_>>(),
        _ => return None,
    };
    if hashes.is_empty() {
        None
    } else {
        Some(hashes)
    }
}

fn companions(case: &Value, root: &Value, base: &Path) -> Vec<(String, PathBuf)> {
    let Some(table) = case
        .get("companions")
        .or_else(|| root.get("companions"))
        .and_then(Value::as_table)
    else {
        return Vec::new();
    };

    table
        .iter()
        .filter_map(|(name, path)| {
            path.as_str()
                .map(|path| (name.clone(), resolve(base, path)))
        })
        .collect()
}

fn sole_artifact(directory: &Path) -> Option<PathBuf> {
    let mut candidates = fs::read_dir(directory)
        .ok()?
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_file()))
        .map(|entry| entry.path())
        .filter(|path| {
            let name = path.file_name().unwrap_or_default().to_string_lossy();
            name != "manifest.toml"
                && !name.ends_with(".hash")
                && !name.ends_with(".salt")
                && !name.ends_with(".py")
                && !name.ends_with(".sh")
                && !name.ends_with(".md")
        })
        .collect::<Vec<_>>();
    candidates.sort();

    if candidates.len() == 1 {
        candidates.pop()
    } else {
        None
    }
}

fn collect_manifests(directory: &Path, manifests: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(directory) else {
        return;
    };
    for entry in entries.filter_map(Result::ok) {
        let path = entry.path();
        if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
            collect_manifests(&path, manifests);
        } else if entry.file_name() == "manifest.toml" {
            manifests.push(path);
        }
    }
}

fn parse_manifest(path: &Path) -> Vec<Case> {
    let Ok(text) = fs::read_to_string(path) else {
        return Vec::new();
    };
    let root = toml::from_str::<Value>(&text).unwrap_or_else(|error| {
        panic!("invalid TOML manifest {}: {error}", path.display());
    });
    let Some(slug) = root.get("type").and_then(Value::as_str) else {
        return Vec::new();
    };
    let Some(descriptor) = registry::by_slug(slug) else {
        return Vec::new();
    };
    let base = path.parent().expect("manifest parent");

    let entries = match root.get("case").and_then(Value::as_array) {
        Some(cases) => cases.iter().collect::<Vec<_>>(),
        None => vec![&root],
    };

    let mut cases = Vec::new();
    for entry in entries {
        let enabled = entry
            .get("e2e")
            .or_else(|| root.get("e2e"))
            .and_then(Value::as_bool)
            .unwrap_or(true);
        if !enabled {
            let reason = string_field(entry, &root, "e2e_reason").unwrap_or_default();
            eprintln!("skipping E2E case for `{slug}`: {reason}");
            continue;
        }

        let artifact = match string_field(entry, &root, "artifact") {
            Some(name) => resolve(base, &name),
            None => match sole_artifact(base) {
                Some(path) => path,
                None => continue,
            },
        };
        if !artifact.is_file() {
            continue;
        }
        cases.push(Case {
            descriptor,
            artifact,
            companions: companions(entry, &root, base),
            hashcat: hash_field(entry, &root, "hashcat"),
            john: hash_field(entry, &root, "john"),
        });
    }
    cases
}

fn artifact_cases() -> Vec<Case> {
    let root = Path::new("tests/fixtures/artifacts");
    let mut manifests = Vec::new();
    collect_manifests(root, &mut manifests);
    manifests.sort();

    manifests
        .iter()
        .flat_map(|path| parse_manifest(path))
        .collect()
}

fn hashcat_modes(case: &Case) -> Vec<u32> {
    case.descriptor
        .all_modes
        .iter()
        .filter_map(|mode| match mode {
            Mode::Hashcat(value) => Some(*value),
            Mode::John(_) => None,
        })
        .collect()
}

fn john_modes(case: &Case) -> Vec<&'static str> {
    case.descriptor
        .all_modes
        .iter()
        .filter_map(|mode| match mode {
            Mode::Hashcat(_) => None,
            Mode::John(value) => Some(*value),
        })
        .collect()
}

fn selected_cases(cases: Vec<Case>, labels: Option<&[String]>, hashcat: bool) -> Vec<Case> {
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
    let mut seen = HashSet::new();
    let mut selected = Vec::new();

    for (index, case) in cases.into_iter().enumerate() {
        let supported = if hashcat {
            case.hashcat.is_some()
                && hashcat_modes(&case)
                    .iter()
                    .any(|mode| labels.is_none_or(|l| l.iter().any(|v| v == &mode.to_string())))
        } else {
            case.john.is_some()
                && john_modes(&case)
                    .iter()
                    .any(|format| labels.is_none_or(|l| l.iter().any(|v| v == format)))
        };
        if !supported {
            continue;
        }

        if subset && !seen.insert(case.descriptor.slug) {
            continue;
        }

        if index % shards == shard {
            selected.push(case);
        }
    }

    selected
}

fn extract(case: &Case, tool: Tool, expected: &[String]) -> Result<Vec<String>, String> {
    let mut artifact = Artifact::from_file(&case.artifact)
        .map_err(|error| format!("read artifact {}: {error}", case.artifact.display()))?;
    for (name, path) in &case.companions {
        let data = fs::read(path)
            .map_err(|error| format!("read companion {}: {error}", path.display()))?;
        artifact = artifact.with_member(name.clone(), MemorySource::new(data));
    }

    let extractor = by_slug(case.descriptor.slug)
        .ok_or_else(|| format!("no extractor registered for `{}`", case.descriptor.slug))?;
    let values = extractor.extract(&artifact).map_err(|error| {
        format!(
            "extract `{}` from {}: {error}",
            case.descriptor.slug,
            case.artifact.display()
        )
    })?;

    let mut seen = HashSet::new();
    let mut hashes = Vec::new();
    for value in values {
        let rendered = value
            .render(&RenderOptions {
                tool,
                ..RenderOptions::default()
            })
            .map_err(|error| {
                format!(
                    "render `{}` from {}: {error}",
                    case.descriptor.slug,
                    case.artifact.display()
                )
            })?;
        if seen.insert(rendered.clone()) {
            hashes.push(rendered);
        }
    }

    if hashes != expected {
        return Err(format!(
            "omniex extraction for `{}` does not match the fixture manifest\nartifact: {}\nexpected: {expected:?}\nactual: {hashes:?}",
            case.descriptor.slug,
            case.artifact.display(),
        ));
    }

    Ok(hashes)
}

fn parse_modes(stdout: &str) -> Vec<u32> {
    stdout
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .filter_map(|token| token.parse().ok())
        .collect()
}

fn text_or_empty(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        "<empty>".to_owned()
    } else {
        String::from_utf8_lossy(bytes).into_owned()
    }
}

fn describe(output: &std::process::Output) -> String {
    format!(
        "status: {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        text_or_empty(&output.stdout),
        text_or_empty(&output.stderr),
    )
}

fn hashcat_binary(slug: &str, mode: u32) -> Option<bool> {
    common::VECTORS
        .iter()
        .find(|vector| vector.slug == slug)?
        .hashcat
        .iter()
        .find(|entry| entry.mode == mode)
        .map(|entry| entry.binary)
}

fn write_hashcat_input(path: &Path, hash: &str, binary: bool) -> Result<(), String> {
    if binary {
        let bytes = hex::decode(hash.trim())
            .map_err(|error| format!("decode binary hash for {}: {error}", path.display()))?;
        fs::write(path, bytes)
    } else {
        fs::write(path, format!("{hash}\n"))
    }
    .map_err(|error| format!("write {}: {error}", path.display()))
}

fn check_hashcat(
    hashcat: &Path,
    potfile: &Path,
    work: &Path,
    case: &Case,
    index: usize,
) -> Result<(), String> {
    let expected = case.hashcat.as_deref().unwrap_or_default();
    let hashes = extract(case, Tool::Hashcat, expected)?;
    let declared = hashcat_modes(case);

    for (line, hash) in hashes.iter().enumerate() {
        let mut representations = Vec::new();
        if declared
            .iter()
            .any(|mode| hashcat_binary(case.descriptor.slug, *mode) == Some(false))
        {
            representations.push(false);
        }
        if declared
            .iter()
            .any(|mode| hashcat_binary(case.descriptor.slug, *mode) == Some(true))
        {
            representations.push(true);
        }
        if representations.is_empty() {
            representations.push(false);
        }

        let mut accepted = Vec::new();
        let mut last_output = None;
        for binary in representations {
            let path = work.join(format!("{index}-{line}-{}.bin", case.descriptor.slug));
            write_hashcat_input(&path, hash, binary)?;
            let session = format!("omniex-e2e-{}-{index}-{line}", std::process::id());

            let identify = Command::new(hashcat)
                .args(["--session", &session, "--identify"])
                .arg(&path)
                .output()
                .map_err(|error| format!("run hashcat --identify: {error}"))?;
            if !identify.status.success() {
                last_output = Some(identify);
                continue;
            }

            let identified = parse_modes(&String::from_utf8_lossy(&identify.stdout));
            let matched = identified
                .iter()
                .copied()
                .filter(|mode| declared.contains(mode))
                .collect::<Vec<_>>();
            if !matched.is_empty() {
                accepted.push((path, session, matched));
                break;
            }
            last_output = Some(identify);
        }

        let Some((path, session, modes)) = accepted.into_iter().next() else {
            let output = last_output.expect("hashcat output");
            return Err(format!(
                "hashcat did not identify a declared mode for `{}` extracted from {}\nhash: {hash}\ndeclared: {declared:?}\n{}",
                case.descriptor.slug,
                case.artifact.display(),
                describe(&output)
            ));
        };

        for mode in modes {
            let show = Command::new(hashcat)
                .args([
                    "--session",
                    &session,
                    "--show",
                    "-m",
                    &mode.to_string(),
                    "--potfile-path",
                ])
                .arg(potfile)
                .arg(&path)
                .output()
                .map_err(|error| format!("run hashcat --show: {error}"))?;
            let combined = format!(
                "{}{}",
                String::from_utf8_lossy(&show.stdout),
                String::from_utf8_lossy(&show.stderr)
            );
            if !show.status.success() || combined.contains("No hashes loaded") {
                return Err(format!(
                    "hashcat --show -m {mode} did not load `{}` extracted from {}\nhash: {hash}\n{}",
                    case.descriptor.slug,
                    case.artifact.display(),
                    describe(&show)
                ));
            }
        }
    }

    Ok(())
}

fn check_john(john: &Path, work: &Path, case: &Case, index: usize) -> Result<(), String> {
    let expected = case.john.as_deref().unwrap_or_default();
    let hashes = extract(case, Tool::John, expected)?;
    let path = work.join(format!("{index}-{}.john.txt", case.descriptor.slug));
    fs::write(&path, format!("{}\n", hashes.join("\n")))
        .map_err(|error| format!("write {}: {error}", path.display()))?;

    let show = Command::new(john)
        .args(["--show=formats"])
        .arg(&path)
        .output()
        .map_err(|error| format!("run john --show=formats: {error}"))?;
    if !show.status.success() {
        return Err(format!(
            "john --show=formats failed for `{}` extracted from {}\n{}",
            case.descriptor.slug,
            case.artifact.display(),
            describe(&show)
        ));
    }

    let stdout = String::from_utf8_lossy(&show.stdout);
    let declared = john_modes(case);
    let found = declared
        .iter()
        .any(|format| stdout.contains(&format!("\"label\":\"{format}\"")));
    if !found {
        return Err(format!(
            "John did not load `{}` as a declared format\ndeclared: {declared:?}\n{}",
            case.descriptor.slug,
            describe(&show)
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

fn run_parallel<F>(cases: &[Case], workers: usize, check: F)
where
    F: Fn(&Case, usize) -> Result<(), String> + Sync,
{
    let next = AtomicUsize::new(0);
    let failures = Mutex::new(Vec::new());

    std::thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| {
                loop {
                    let index = next.fetch_add(1, Ordering::Relaxed);
                    let Some(case) = cases.get(index) else {
                        break;
                    };
                    if let Err(message) = check(case, index) {
                        eprintln!("extract-to-cracker failure:\n{message}");
                        failures.lock().expect("failure list").push(message);
                    }
                }
            });
        }
    });

    let failures = failures.into_inner().expect("failure list");
    assert!(
        failures.is_empty(),
        "{} extract-to-cracker failure(s):\n{}",
        failures.len(),
        failures.join("\n")
    );
}

#[test]
#[ignore = "requires a hashcat build"]
fn hashcat_loads_extracted_artifacts() {
    let Some(hashcat) = reference("OMNIEX_HASHCAT", "hashcat") else {
        return;
    };
    let selected = selected_modes();
    let cases = selected_cases(artifact_cases(), selected.as_deref(), true);
    if cases.is_empty() {
        return;
    }

    let work = work_dir("extract-cracker-e2e-hashcat");
    let potfile = work.join("empty.pot");
    fs::File::create(&potfile).expect("create empty potfile");
    let workers = worker_count(cases.len());

    eprintln!(
        "hashcat extract-to-cracker: {} case(s), {workers} worker(s)",
        cases.len()
    );
    run_parallel(&cases, workers, |case, index| {
        check_hashcat(&hashcat, &potfile, &work, case, index)
    });
}

#[test]
#[ignore = "requires a John jumbo build"]
fn john_loads_extracted_artifacts() {
    let Some(john) = reference("OMNIEX_JOHN", "john") else {
        return;
    };
    let selected = selected_modes();
    let cases = selected_cases(artifact_cases(), selected.as_deref(), false);
    if cases.is_empty() {
        return;
    }

    let work = work_dir("extract-cracker-e2e-john");
    let workers = worker_count(cases.len());

    eprintln!(
        "John extract-to-cracker: {} case(s), {workers} worker(s)",
        cases.len()
    );
    run_parallel(&cases, workers, |case, index| {
        check_john(&john, &work, case, index)
    });
}
