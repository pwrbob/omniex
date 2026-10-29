//! Parse, render, describe, and mode tests for the reference slice.

use omniex::types::{Md5, SaltedMd5};
use omniex::{
    Describe, Mode, ModeCompat, Parse, ParseErrorKind, ParseOptions, Render, RenderOptions, Tool,
};

const MD5_HASH: &str = "8743b52063cd84097a65d1633f5c74f5";
const SALTED_MD5_HASH: &str = "3d83c8e717ff0e7ecfe187f088d69954:343141";

fn parse_opts(tool: Tool) -> ParseOptions {
    ParseOptions {
        tool,
        ..ParseOptions::default()
    }
}

fn render_opts(tool: Tool) -> RenderOptions {
    RenderOptions {
        tool,
        ..RenderOptions::default()
    }
}

#[test]
fn md5_parses_and_renders_canonically() {
    for tool in [Tool::Hashcat, Tool::John] {
        let value = Md5::parse(MD5_HASH, &parse_opts(tool)).expect("canonical md5 parses");
        assert_eq!(value.render(&render_opts(tool)), MD5_HASH);
    }
}

#[test]
fn md5_round_trips() {
    let value = Md5::parse(MD5_HASH, &ParseOptions::default()).unwrap();
    let rendered = value.render(&RenderOptions::default());
    let again = Md5::parse(&rendered, &ParseOptions::default()).unwrap();
    assert_eq!(value, again);
}

#[test]
fn md5_accepts_uppercase_and_renders_lowercase() {
    let value = Md5::parse(&MD5_HASH.to_uppercase(), &ParseOptions::default()).unwrap();
    assert_eq!(value.render(&RenderOptions::default()), MD5_HASH);
}

#[test]
fn md5_rejects_empty_input() {
    let error = Md5::parse("", &ParseOptions::default()).unwrap_err();
    assert_eq!(error.kind, ParseErrorKind::Empty);
    assert_eq!(error.offset, 0);
}

#[test]
fn md5_rejects_wrong_length() {
    let error = Md5::parse("abc", &ParseOptions::default()).unwrap_err();
    assert_eq!(error.kind, ParseErrorKind::InvalidLength);
    assert_eq!(error.offset, 0);
}

#[test]
fn md5_reports_invalid_digit_offset() {
    let mut input = MD5_HASH.to_owned();
    input.replace_range(5..6, "z");
    let error = Md5::parse(&input, &ParseOptions::default()).unwrap_err();
    assert_eq!(error.kind, ParseErrorKind::InvalidHex);
    assert_eq!(error.offset, 5);
}

#[test]
fn salted_md5_parses_and_renders_canonically() {
    for tool in [Tool::Hashcat, Tool::John] {
        let value = SaltedMd5::parse(SALTED_MD5_HASH, &parse_opts(tool))
            .expect("canonical salted md5 parses");
        assert_eq!(value.render(&render_opts(tool)), SALTED_MD5_HASH);
    }
}

#[test]
fn salted_md5_round_trips() {
    let value = SaltedMd5::parse(SALTED_MD5_HASH, &ParseOptions::default()).unwrap();
    let rendered = value.render(&RenderOptions::default());
    let again = SaltedMd5::parse(&rendered, &ParseOptions::default()).unwrap();
    assert_eq!(value, again);
}

#[test]
fn salted_md5_allows_empty_salt() {
    let input = format!("{MD5_HASH}:");
    let value = SaltedMd5::parse(&input, &ParseOptions::default()).unwrap();
    assert!(value.salt.is_empty());
    assert_eq!(value.render(&RenderOptions::default()), input);
}

#[test]
fn salted_md5_requires_separator() {
    let error = SaltedMd5::parse(MD5_HASH, &ParseOptions::default()).unwrap_err();
    assert_eq!(error.kind, ParseErrorKind::InvalidCharacter);
    assert_eq!(error.offset, MD5_HASH.len());
}

#[test]
fn salted_md5_accepts_non_hex_ascii_salt() {
    let input = format!("{MD5_HASH}:abcXYZ");
    let value = SaltedMd5::parse(&input, &ParseOptions::default()).unwrap();
    assert_eq!(value.salt, "abcXYZ");
    assert_eq!(value.render(&RenderOptions::default()), input);
}

#[test]
fn salted_md5_rejects_extra_separator() {
    let input = format!("{MD5_HASH}:aa:bbc");
    let error = SaltedMd5::parse(&input, &ParseOptions::default()).unwrap_err();
    assert_eq!(error.kind, ParseErrorKind::InvalidCharacter);
    assert_eq!(error.offset, MD5_HASH.len() + 3);
}

#[test]
fn md5_describe_reports_one_field() {
    let value = Md5::parse(MD5_HASH, &ParseOptions::default()).unwrap();
    let described = value.describe();

    assert_eq!(described.len(), 1);
    assert_eq!(described[0].field.name, "digest");
    assert_eq!(described[0].value, MD5_HASH);
    assert!(!described[0].field.description.is_empty());
}

#[test]
fn salted_md5_describe_reports_both_fields() {
    let value = SaltedMd5::parse(SALTED_MD5_HASH, &ParseOptions::default()).unwrap();
    let described = value.describe();

    assert_eq!(described.len(), 2);
    assert_eq!(described[0].field.name, "digest");
    assert_eq!(described[1].field.name, "salt");
    assert_eq!(described[1].value, "343141");
}

#[test]
fn modes_are_a_subset_of_declared_modes() {
    let values: Vec<Box<dyn ModeCompat>> = vec![
        Box::new(Md5::parse(MD5_HASH, &ParseOptions::default()).unwrap()),
        Box::new(SaltedMd5::parse(SALTED_MD5_HASH, &ParseOptions::default()).unwrap()),
    ];

    for value in values {
        let modes = value.modes();
        assert!(!modes.is_empty());
        for mode in modes {
            assert!(
                Md5::DESCRIPTOR.all_modes.contains(&mode)
                    || SaltedMd5::DESCRIPTOR.all_modes.contains(&mode)
            );
        }
    }
}

#[test]
fn declared_modes_match_the_design() {
    assert_eq!(
        Md5::DESCRIPTOR.all_modes,
        &[Mode::Hashcat(0), Mode::Hashcat(70), Mode::John("Raw-MD5")]
    );
    assert_eq!(
        SaltedMd5::DESCRIPTOR.all_modes,
        &[
            Mode::Hashcat(10),
            Mode::Hashcat(11),
            Mode::Hashcat(12),
            Mode::Hashcat(20),
            Mode::Hashcat(21),
            Mode::Hashcat(23),
            Mode::Hashcat(24),
            Mode::Hashcat(30),
            Mode::Hashcat(40),
            Mode::Hashcat(3800),
        ]
    );
}
