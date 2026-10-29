//! Per-type behavior: field metadata, boundaries, and invalid input.

mod common;

use common::{VECTORS, vector_for};
use omniex::types::{
    ArubaSha1, Blake2b512, DjangoSha1, Episerver, HmacMd5, HmacSha1, JuniperScreenos, LdapSha1,
    LdapSsha1, MacosSha1, Md4, Md5Crypt, Mssql2000, OracleSha1, Phpass, SaltedMd5,
};
use omniex::{ModeCompat, Parse, ParseErrorKind, ParseOptions, RenderOptions, registry};

#[test]
fn every_type_describes_every_field() {
    let expected: &[(&str, &[&str])] = &[
        ("md4", &["digest"]),
        ("md5", &["digest"]),
        ("salted-md5", &["digest", "salt"]),
        ("hmac-md5", &["digest", "key"]),
        ("sha1", &["digest"]),
        ("salted-sha1", &["digest", "salt"]),
        ("hmac-sha1", &["digest", "key"]),
        ("oracle-sha1", &["digest", "salt"]),
        ("ldap-sha1", &["digest"]),
        ("ldap-ssha1", &["digest", "salt"]),
        ("macos-sha1", &["salt", "digest"]),
        ("django-sha1", &["salt", "digest"]),
        ("aruba-sha1", &["salt", "digest"]),
        ("mssql-2000", &["salt", "padding", "digest"]),
        ("mssql-2005", &["salt", "digest"]),
        ("peoplesoft-sha1", &["digest"]),
        ("episerver", &["salt", "digest"]),
        ("mysql323", &["digest"]),
        ("phpass", &["prefix", "iterations", "salt", "digest"]),
        ("md5crypt", &["rounds", "salt", "digest"]),
        ("juniper-ive", &["signature"]),
        ("juniper-screenos", &["digest", "salt"]),
        ("blake2b-512", &["digest"]),
        ("salted-blake2b-512", &["digest", "salt"]),
    ];

    for (slug, names) in expected {
        let descriptor = registry::by_slug(slug).expect("registered");
        let vector = vector_for(descriptor).expect("vector");
        let entry = vector.hashcat.first().expect("hashcat vector");
        let value = registry::parse(descriptor, entry.hash, &ParseOptions::default())
            .unwrap_or_else(|error| panic!("`{slug}` failed to parse: {error}"));
        let described = value.describe();

        assert_eq!(described.len(), names.len(), "`{slug}` field count changed");
        for (entry, name) in described.iter().zip(*names) {
            assert_eq!(entry.field.name, *name, "`{slug}` field order changed");
            assert!(
                !entry.field.description.is_empty(),
                "`{slug}` field `{name}` has no description"
            );
            assert!(!entry.value.is_empty(), "`{slug}` field `{name}` is empty");
        }
    }
}

#[test]
fn invalid_inputs_return_stable_error_kinds() {
    let zeros = |len: usize| "0".repeat(len);
    let cases: Vec<(String, String, ParseErrorKind)> = vec![
        ("md4".into(), "".into(), ParseErrorKind::Empty),
        ("md4".into(), "abcd".into(), ParseErrorKind::InvalidLength),
        ("md5".into(), "".into(), ParseErrorKind::Empty),
        ("md5".into(), "zz".into(), ParseErrorKind::InvalidLength),
        (
            "salted-md5".into(),
            "abc".into(),
            ParseErrorKind::InvalidCharacter,
        ),
        (
            "salted-md5".into(),
            format!("{}:x", "z".repeat(32)),
            ParseErrorKind::InvalidHex,
        ),
        (
            "salted-md5".into(),
            format!("{}:a:b", zeros(32)),
            ParseErrorKind::InvalidCharacter,
        ),
        (
            "hmac-md5".into(),
            "abc".into(),
            ParseErrorKind::InvalidCharacter,
        ),
        (
            "hmac-md5".into(),
            format!("{}:a:b", zeros(32)),
            ParseErrorKind::InvalidCharacter,
        ),
        ("sha1".into(), "abc".into(), ParseErrorKind::InvalidLength),
        (
            "salted-sha1".into(),
            "abc".into(),
            ParseErrorKind::InvalidCharacter,
        ),
        (
            "hmac-sha1".into(),
            "abc".into(),
            ParseErrorKind::InvalidCharacter,
        ),
        (
            "oracle-sha1".into(),
            format!("{}:abcd", zeros(40)),
            ParseErrorKind::InvalidLength,
        ),
        (
            "ldap-sha1".into(),
            "abc".into(),
            ParseErrorKind::InvalidCharacter,
        ),
        (
            "ldap-sha1".into(),
            "{SHA}!!!!".into(),
            ParseErrorKind::InvalidBase64,
        ),
        (
            "ldap-sha1".into(),
            "{SHA}YWJj".into(),
            ParseErrorKind::InvalidLength,
        ),
        (
            "ldap-ssha1".into(),
            "abc".into(),
            ParseErrorKind::InvalidCharacter,
        ),
        (
            "ldap-ssha1".into(),
            "{SSHA}YWJj".into(),
            ParseErrorKind::InvalidLength,
        ),
        (
            "macos-sha1".into(),
            "abc".into(),
            ParseErrorKind::InvalidLength,
        ),
        (
            "django-sha1".into(),
            "sha2$x$y".into(),
            ParseErrorKind::InvalidCharacter,
        ),
        (
            "django-sha1".into(),
            "sha1$x$zz".into(),
            ParseErrorKind::InvalidLength,
        ),
        (
            "aruba-sha1".into(),
            "abc".into(),
            ParseErrorKind::InvalidLength,
        ),
        (
            "aruba-sha1".into(),
            format!("{}99{}", zeros(8), zeros(40)),
            ParseErrorKind::InvalidCharacter,
        ),
        (
            "mssql-2000".into(),
            "abc".into(),
            ParseErrorKind::InvalidCharacter,
        ),
        (
            "mssql-2000".into(),
            "0x0100abcd".into(),
            ParseErrorKind::InvalidLength,
        ),
        (
            "mssql-2005".into(),
            "abc".into(),
            ParseErrorKind::InvalidCharacter,
        ),
        (
            "mssql-2005".into(),
            "0x0100abcd".into(),
            ParseErrorKind::InvalidLength,
        ),
        (
            "peoplesoft-sha1".into(),
            "!!!!".into(),
            ParseErrorKind::InvalidBase64,
        ),
        (
            "peoplesoft-sha1".into(),
            "YWJj".into(),
            ParseErrorKind::InvalidLength,
        ),
        (
            "episerver".into(),
            "abc".into(),
            ParseErrorKind::InvalidCharacter,
        ),
        (
            "episerver".into(),
            "$episerver$*0*MjEwNA==*!!!!".into(),
            ParseErrorKind::InvalidBase64,
        ),
        (
            "mysql323".into(),
            "abcd".into(),
            ParseErrorKind::InvalidLength,
        ),
        (
            "phpass".into(),
            "abc".into(),
            ParseErrorKind::InvalidCharacter,
        ),
        (
            "phpass".into(),
            "$P$short".into(),
            ParseErrorKind::InvalidLength,
        ),
        (
            "phpass".into(),
            format!("$P$!{}", "a".repeat(30)),
            ParseErrorKind::InvalidCharacter,
        ),
        (
            "md5crypt".into(),
            "abc".into(),
            ParseErrorKind::InvalidCharacter,
        ),
        (
            "md5crypt".into(),
            "$1$rounds=x$salt$hash".into(),
            ParseErrorKind::InvalidCharacter,
        ),
        (
            "md5crypt".into(),
            "$1$salt$short".into(),
            ParseErrorKind::InvalidLength,
        ),
        (
            "juniper-ive".into(),
            "!!!!".into(),
            ParseErrorKind::InvalidBase64,
        ),
        (
            "juniper-screenos".into(),
            "short:123".into(),
            ParseErrorKind::InvalidLength,
        ),
        (
            "juniper-screenos".into(),
            format!("{}:abc", "n".repeat(30)),
            ParseErrorKind::InvalidCharacter,
        ),
        (
            "blake2b-512".into(),
            "$BLAKE2$abcd".into(),
            ParseErrorKind::InvalidLength,
        ),
        (
            "blake2b-512".into(),
            "abcd".into(),
            ParseErrorKind::InvalidCharacter,
        ),
        (
            "salted-blake2b-512".into(),
            "$BLAKE2$abcd".into(),
            ParseErrorKind::InvalidCharacter,
        ),
    ];

    for (slug, input, kind) in cases {
        let descriptor = registry::by_slug(&slug).expect("registered");
        match registry::parse(descriptor, &input, &ParseOptions::default()) {
            Ok(_) => panic!("`{slug}` accepted invalid input `{input}`"),
            Err(error) => assert_eq!(
                error.kind, kind,
                "`{slug}` returned the wrong kind for `{input}`: {error:?}"
            ),
        }
    }
}

#[test]
fn parsers_never_panic_on_arbitrary_input() {
    let inputs = [
        "",
        ":",
        "$$",
        "{}",
        "0x",
        "$1$",
        "$P$",
        "$BLAKE2$",
        "$episerver$",
        "sha1$",
        "{SHA}",
        "{SSHA}",
        "\u{00e9}",
        "::::::",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ];

    for descriptor in registry::all() {
        for input in inputs {
            let _ = registry::parse(descriptor, input, &ParseOptions::default());
        }
    }
}

#[test]
fn structured_fields_are_decoded_not_kept_as_whole_strings() {
    let opts = ParseOptions::default();

    let oracle = OracleSha1::parse(
        "63ec5f6113843f5d229e2d49c068d983a9670d02:57677783202322766743",
        &opts,
    )
    .unwrap();
    assert_eq!(oracle.salt.len(), 10);
    assert_eq!(omniex::format::hex(oracle.salt), "57677783202322766743");

    let ldap = LdapSha1::parse("{SHA}uJ6qx+YUFzQbcQtyd2gpTQ5qJ3s=", &opts).unwrap();
    assert_eq!(
        omniex::format::hex(ldap.digest),
        "b89eaac7e61417341b710b727768294d0e6a277b"
    );

    let ssha = LdapSsha1::parse("{SSHA}FLzWcQqyle6Mo7NvrwXCMAmRzXQxNjYxMTYzNw==", &opts).unwrap();
    assert_eq!(ssha.salt.len(), 8);

    let macos =
        MacosSha1::parse("86586886b8bd3c379d2e176243a7225e6aae969d293fe9a9", &opts).unwrap();
    assert_eq!(omniex::format::hex(macos.salt), "86586886");

    let django =
        DjangoSha1::parse("sha1$fe76b$02d5916550edf7fc8c886f044887f4b1abf9b013", &opts).unwrap();
    assert_eq!(django.salt, "fe76b");

    let aruba =
        ArubaSha1::parse("83377286015bcebb857b23b94331e2b316b6ecbe9fbf26c4fc", &opts).unwrap();
    assert_eq!(omniex::format::hex(aruba.salt), "83377286");

    let mssql = Mssql2000::parse(
        "0x0100778883860000000000000000000000000000000000000000eda3604e067a06f2732b05b9cb90b8a710996939",
        &opts,
    )
    .unwrap();
    assert_eq!(omniex::format::hex(mssql.salt), "77888386");
    assert_eq!(mssql.padding, [0u8; 20]);

    let phpass = Phpass::parse("$P$946647711V1klyitUYhtB8Yw5DMA/w.", &opts).unwrap();
    assert_eq!(phpass.prefix, "$P$");
    assert_eq!(phpass.iterations, 11);
    assert_eq!(phpass.salt, "46647711");
    assert_eq!(phpass.digest, "V1klyitUYhtB8Yw5DMA/w.");

    let md5crypt = Md5Crypt::parse("$1$38652870$DUjsu4TTlTsOe/xxZ05uf/", &opts).unwrap();
    assert_eq!(md5crypt.rounds, 0);
    assert_eq!(md5crypt.salt, "38652870");
    assert_eq!(md5crypt.digest, "DUjsu4TTlTsOe/xxZ05uf/");

    let blake = Blake2b512::parse(
        "$BLAKE2$296c269e70ac5f0095e6fb47693480f0f7b97ccd0307f5c3bfa4df8f5ca5c9308a0e7108e80a0a9c0ebb715e8b7109b072046c6cd5e155b4cfd2f27216283b1e",
        &opts,
    )
    .unwrap();
    assert_eq!(blake.digest.len(), 64);

    let salted = SaltedMd5::parse("3d83c8e717ff0e7ecfe187f088d69954:343141", &opts).unwrap();
    assert_eq!(salted.salt, "343141");

    let hmac = HmacMd5::parse("e28e4e37e972a945e464b5226053bac0:40", &opts).unwrap();
    assert_eq!(hmac.key, "40");

    let hmac_sha1 =
        HmacSha1::parse("02b256705348a28b1d6c0f063907979f7e0c82f8:10323", &opts).unwrap();
    assert_eq!(hmac_sha1.key, "10323");

    let md4 = Md4::parse("afe04867ec7a3845145579a95f72eca7", &opts).unwrap();
    assert_eq!(md4.digest.len(), 16);

    let episerver =
        Episerver::parse("$episerver$*0*MjEwNA==*ZUgAmuaYTqAvisD0A427FA3oaWU", &opts).unwrap();
    assert_eq!(episerver.salt, b"2104");
    assert_eq!(episerver.digest.len(), 20);

    let screenos =
        JuniperScreenos::parse("nKjiFErqK7TPcZdFZsZMNWPtw4Pv8n:26506173", &opts).unwrap();
    assert_eq!(screenos.salt, "26506173");
    assert_eq!(screenos.digest.len(), 30);
}

#[test]
fn modes_are_reported_for_parsed_values() {
    for vector in VECTORS {
        let descriptor = registry::by_slug(vector.slug).expect("registered");
        for entry in vector.hashcat {
            let value = registry::parse(descriptor, entry.hash, &ParseOptions::default())
                .unwrap_or_else(|error| panic!("`{}`: {error}", vector.slug));
            assert!(value.modes().contains(&omniex::Mode::Hashcat(entry.mode)));
        }
    }
}

#[test]
fn render_is_stable_across_repeated_round_trips() {
    for vector in VECTORS {
        let descriptor = registry::by_slug(vector.slug).expect("registered");
        for entry in vector.hashcat {
            let parsed = registry::parse(descriptor, entry.hash, &ParseOptions::default()).unwrap();
            let first = parsed.render(&RenderOptions::default());
            let reparsed = registry::parse(descriptor, &first, &ParseOptions::default()).unwrap();
            assert_eq!(reparsed.render(&RenderOptions::default()), first);
        }
    }
}

#[test]
fn describe_is_not_empty_for_any_type() {
    for descriptor in registry::all() {
        let vector = vector_for(descriptor).expect("vector");
        let value =
            registry::parse(descriptor, vector.hashcat[0].hash, &ParseOptions::default()).unwrap();
        assert!(!value.describe().is_empty());
    }
}

#[test]
fn value_dependent_modes_track_salt_and_key_limits() {
    let opts = ParseOptions::default();
    let digest32 = "0".repeat(32);

    let short = SaltedMd5::parse(&format!("{digest32}:00"), &opts).unwrap();
    let short_modes = short.modes();
    assert!(short_modes.contains(&omniex::Mode::Hashcat(21)));
    assert!(short_modes.contains(&omniex::Mode::Hashcat(24)));
    assert!(!short_modes.contains(&omniex::Mode::Hashcat(11)));

    let long = SaltedMd5::parse(&format!("{digest32}:{}", "1".repeat(32)), &opts).unwrap();
    let long_modes = long.modes();
    assert!(long_modes.contains(&omniex::Mode::Hashcat(11)));
    assert!(long_modes.contains(&omniex::Mode::Hashcat(12)));
    assert!(!long_modes.contains(&omniex::Mode::Hashcat(21)));

    let too_long = SaltedMd5::parse(&format!("{digest32}:{}", "a".repeat(300)), &opts).unwrap();
    assert!(too_long.modes().is_empty());

    let sha =
        omniex::types::SaltedSha1::parse(&format!("{}:{}", "0".repeat(40), "a".repeat(30)), &opts)
            .unwrap();
    let sha_modes = sha.modes();
    assert!(sha_modes.contains(&omniex::Mode::Hashcat(110)));
    assert!(!sha_modes.contains(&omniex::Mode::Hashcat(130)));

    let hmac = HmacMd5::parse(&format!("{}:{}", "0".repeat(32), "k".repeat(300)), &opts).unwrap();
    assert!(hmac.modes().is_empty());

    let blake = omniex::types::SaltedBlake2b512::parse(
        &format!("$BLAKE2${}:{}", "0".repeat(128), "s".repeat(200)),
        &opts,
    )
    .unwrap();
    assert!(blake.modes().is_empty());
}

#[test]
fn modes_fn_never_reports_undeclared_modes() {
    for descriptor in registry::all() {
        let vector = vector_for(descriptor).expect("vector");
        let mut samples = vec![vector.hashcat[0].hash.to_owned()];
        if let Some(entry) = vector.john.first() {
            samples.push(entry.hash.to_owned());
        }

        for sample in samples {
            if let Ok(value) = registry::parse(descriptor, &sample, &ParseOptions::default()) {
                for mode in value.modes() {
                    assert!(
                        descriptor.all_modes.contains(&mode),
                        "`{}` reported undeclared mode {mode:?}",
                        descriptor.slug
                    );
                }
            }
        }
    }
}
