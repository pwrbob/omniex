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
        ("ntlm", &["digest"]),
        ("dcc", &["digest", "username"]),
        ("sha224", &["digest"]),
        ("sha256", &["digest"]),
        ("salted-sha256", &["digest", "salt"]),
        ("hmac-sha256", &["digest", "key"]),
        ("hmailserver", &["salt", "digest"]),
        ("sha512", &["digest"]),
        ("salted-sha512", &["digest", "salt"]),
        ("hmac-sha512", &["digest", "key"]),
        ("ldap-ssha256", &["digest", "salt"]),
        ("episerver-net4", &["salt", "digest"]),
        ("descrypt", &["crypt"]),
        ("apr1", &["rounds", "salt", "digest"]),
        ("ldap-ssha512", &["digest", "salt"]),
        ("macos-sha512", &["salt", "digest"]),
        ("mssql-2012", &["salt", "digest"]),
        ("sha512crypt", &["rounds", "salt", "digest"]),
        ("dcc2", &["iterations", "username", "digest"]),
        ("cisco-pix", &["crypt"]),
        ("cisco-asa", &["crypt", "salt"]),
        ("phps", &["salt", "digest"]),
        (
            "wpa-pmkid",
            &[
                "kind",
                "pmkid",
                "access_point",
                "station",
                "essid",
                "extras",
            ],
        ),
        ("lm", &["digest"]),
        ("oracle-h", &["digest", "salt"]),
        ("bcrypt", &["prefix", "cost", "salt", "digest"]),
        ("sunmd5", &["rounds", "salt", "digest"]),
        ("mediawiki-b", &["salt", "digest"]),
        ("md5-two-salts", &["digest", "salt1", "salt2"]),
        ("iscsi-chap", &["digest", "challenge", "chap_id"]),
        ("half-md5", &["digest"]),
        (
            "ike-psk-md5",
            &[
                "message_0",
                "message_1",
                "message_2",
                "message_3",
                "message_4",
                "message_5",
                "nonce_0",
                "nonce_1",
                "digest",
            ],
        ),
        (
            "ike-psk-sha1",
            &[
                "message_0",
                "message_1",
                "message_2",
                "message_3",
                "message_4",
                "message_5",
                "nonce_0",
                "nonce_1",
                "digest",
            ],
        ),
        (
            "netntlmv1",
            &[
                "username",
                "domain",
                "lm_response",
                "nt_response",
                "challenge",
            ],
        ),
        (
            "netntlmv2",
            &["username", "domain", "challenge", "nt_proof", "blob"],
        ),
        ("cisco-ios4", &["signature"]),
        ("samsung-android", &["digest", "salt"]),
        ("ripemd-160", &["digest"]),
        ("whirlpool", &["digest"]),
        ("gost", &["digest"]),
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
        ("ntlm".into(), "".into(), ParseErrorKind::Empty),
        ("ntlm".into(), "abcd".into(), ParseErrorKind::InvalidLength),
        (
            "dcc".into(),
            "abcd".into(),
            ParseErrorKind::InvalidCharacter,
        ),
        (
            "dcc".into(),
            format!("{}:a:b", zeros(32)),
            ParseErrorKind::InvalidCharacter,
        ),
        (
            "sha224".into(),
            "abcd".into(),
            ParseErrorKind::InvalidLength,
        ),
        (
            "sha256".into(),
            "abcd".into(),
            ParseErrorKind::InvalidLength,
        ),
        (
            "salted-sha256".into(),
            "abcd".into(),
            ParseErrorKind::InvalidCharacter,
        ),
        (
            "salted-sha256".into(),
            format!("{}:a:b", zeros(64)),
            ParseErrorKind::InvalidCharacter,
        ),
        (
            "hmac-sha256".into(),
            "abcd".into(),
            ParseErrorKind::InvalidCharacter,
        ),
        (
            "hmac-sha256".into(),
            format!("{}:a:b", zeros(64)),
            ParseErrorKind::InvalidCharacter,
        ),
        (
            "hmailserver".into(),
            "abcd".into(),
            ParseErrorKind::InvalidLength,
        ),
        (
            "sha512".into(),
            "abcd".into(),
            ParseErrorKind::InvalidLength,
        ),
        (
            "salted-sha512".into(),
            "abcd".into(),
            ParseErrorKind::InvalidCharacter,
        ),
        (
            "salted-sha512".into(),
            format!("{}:a:b", zeros(128)),
            ParseErrorKind::InvalidCharacter,
        ),
        (
            "hmac-sha512".into(),
            "abcd".into(),
            ParseErrorKind::InvalidCharacter,
        ),
        (
            "hmac-sha512".into(),
            format!("{}:a:b", zeros(128)),
            ParseErrorKind::InvalidCharacter,
        ),
        (
            "ldap-ssha256".into(),
            "abc".into(),
            ParseErrorKind::InvalidCharacter,
        ),
        (
            "ldap-ssha256".into(),
            "{SSHA256}YWJj".into(),
            ParseErrorKind::InvalidLength,
        ),
        (
            "episerver-net4".into(),
            "abc".into(),
            ParseErrorKind::InvalidCharacter,
        ),
        (
            "episerver-net4".into(),
            "$episerver$*1*MjEwNA==*!!!!".into(),
            ParseErrorKind::InvalidBase64,
        ),
        (
            "descrypt".into(),
            "short".into(),
            ParseErrorKind::InvalidLength,
        ),
        (
            "descrypt".into(),
            "!!!!!!!!!!!!!".into(),
            ParseErrorKind::InvalidCharacter,
        ),
        (
            "apr1".into(),
            "abc".into(),
            ParseErrorKind::InvalidCharacter,
        ),
        (
            "apr1".into(),
            "$apr1$rounds=x$salt$hash".into(),
            ParseErrorKind::InvalidCharacter,
        ),
        (
            "apr1".into(),
            "$apr1$salt$short".into(),
            ParseErrorKind::InvalidLength,
        ),
        (
            "ldap-ssha512".into(),
            "abc".into(),
            ParseErrorKind::InvalidCharacter,
        ),
        (
            "ldap-ssha512".into(),
            "{SSHA512}YWJj".into(),
            ParseErrorKind::InvalidLength,
        ),
        (
            "macos-sha512".into(),
            "abc".into(),
            ParseErrorKind::InvalidLength,
        ),
        (
            "mssql-2012".into(),
            "abc".into(),
            ParseErrorKind::InvalidCharacter,
        ),
        (
            "mssql-2012".into(),
            "0x0200abcd".into(),
            ParseErrorKind::InvalidLength,
        ),
        (
            "sha512crypt".into(),
            "abc".into(),
            ParseErrorKind::InvalidCharacter,
        ),
        (
            "sha512crypt".into(),
            "$6$salt$short".into(),
            ParseErrorKind::InvalidLength,
        ),
        (
            "dcc2".into(),
            "abc".into(),
            ParseErrorKind::InvalidCharacter,
        ),
        (
            "dcc2".into(),
            "$DCC2$x#user#00".into(),
            ParseErrorKind::InvalidCharacter,
        ),
        (
            "cisco-pix".into(),
            "short".into(),
            ParseErrorKind::InvalidLength,
        ),
        (
            "cisco-pix".into(),
            "!!!!!!!!!!!!!!!!".into(),
            ParseErrorKind::InvalidCharacter,
        ),
        (
            "cisco-asa".into(),
            "short:1".into(),
            ParseErrorKind::InvalidLength,
        ),
        (
            "cisco-asa".into(),
            "YjDBNr.A0AN7DA8s:abcd".into(),
            ParseErrorKind::InvalidCharacter,
        ),
        (
            "phps".into(),
            "abc".into(),
            ParseErrorKind::InvalidCharacter,
        ),
        (
            "phps".into(),
            "$PHPS$abc$00".into(),
            ParseErrorKind::InvalidCharacter,
        ),
        (
            "wpa-pmkid".into(),
            "abcd".into(),
            ParseErrorKind::InvalidCharacter,
        ),
        (
            "wpa-pmkid".into(),
            "WPA*01*abcd".into(),
            ParseErrorKind::InvalidLength,
        ),
        ("lm".into(), "abcd".into(), ParseErrorKind::InvalidLength),
        (
            "oracle-h".into(),
            "abcd".into(),
            ParseErrorKind::InvalidCharacter,
        ),
        (
            "oracle-h".into(),
            "abcd:12".into(),
            ParseErrorKind::InvalidLength,
        ),
        ("bcrypt".into(), "abc".into(), ParseErrorKind::InvalidLength),
        (
            "bcrypt".into(),
            "$2z$05$MBCzKhG1KhezLh.0LRa0Kuw12nLJtpHy6DIaU.JAnqJUDYspHC.Ou".into(),
            ParseErrorKind::InvalidCharacter,
        ),
        (
            "sunmd5".into(),
            "abc".into(),
            ParseErrorKind::InvalidCharacter,
        ),
        (
            "sunmd5".into(),
            "$md5,rounds=x$salt$$hash".into(),
            ParseErrorKind::InvalidCharacter,
        ),
        (
            "mediawiki-b".into(),
            "abc".into(),
            ParseErrorKind::InvalidCharacter,
        ),
        (
            "mediawiki-b".into(),
            "$B$abc$00".into(),
            ParseErrorKind::InvalidCharacter,
        ),
        (
            "md5-two-salts".into(),
            "abcd".into(),
            ParseErrorKind::InvalidCharacter,
        ),
        (
            "md5-two-salts".into(),
            format!("{}:a", zeros(32)),
            ParseErrorKind::InvalidCharacter,
        ),
        (
            "iscsi-chap".into(),
            "abcd".into(),
            ParseErrorKind::InvalidCharacter,
        ),
        (
            "iscsi-chap".into(),
            format!("{}:zz:00", zeros(32)),
            ParseErrorKind::InvalidHex,
        ),
        (
            "half-md5".into(),
            "abcd".into(),
            ParseErrorKind::InvalidLength,
        ),
        (
            "ike-psk-md5".into(),
            "abc".into(),
            ParseErrorKind::InvalidLength,
        ),
        (
            "ike-psk-sha1".into(),
            "abc".into(),
            ParseErrorKind::InvalidLength,
        ),
        (
            "netntlmv1".into(),
            "abc".into(),
            ParseErrorKind::InvalidLength,
        ),
        (
            "netntlmv2".into(),
            "abc".into(),
            ParseErrorKind::InvalidLength,
        ),
        (
            "cisco-ios4".into(),
            "abc".into(),
            ParseErrorKind::InvalidLength,
        ),
        (
            "samsung-android".into(),
            "abc".into(),
            ParseErrorKind::InvalidCharacter,
        ),
        (
            "authme-sha256".into(),
            "abc".into(),
            ParseErrorKind::InvalidCharacter,
        ),
        (
            "netwitness-sha256".into(),
            "abcd:00".into(),
            ParseErrorKind::InvalidLength,
        ),
        (
            "sha1-utf16-username-salt".into(),
            format!("{}:salt:zz", zeros(40)),
            ParseErrorKind::InvalidHex,
        ),
        (
            "md5-two-nested-salts".into(),
            format!("{}:only-one", zeros(32)),
            ParseErrorKind::InvalidLength,
        ),
        (
            "md5-two-nested-salts".into(),
            format!("{}:a:b:c", zeros(32)),
            ParseErrorKind::InvalidLength,
        ),
        (
            "aix-smd5".into(),
            "{smd5}short".into(),
            ParseErrorKind::InvalidCharacter,
        ),
        (
            "ssha1-aix".into(),
            "{ssha1}06$salt$short".into(),
            ParseErrorKind::InvalidLength,
        ),
        (
            "sha256crypt".into(),
            "$5$salt$short".into(),
            ParseErrorKind::InvalidLength,
        ),
        (
            "citrix-netscaler-sha1".into(),
            "2short".into(),
            ParseErrorKind::InvalidLength,
        ),
        (
            "wbb3".into(),
            format!("{}:abc", zeros(40)),
            ParseErrorKind::InvalidCharacter,
        ),
        (
            "qnx-md5".into(),
            "@m@abcd@12345678".into(),
            ParseErrorKind::InvalidLength,
        ),
        (
            "pbkdf2-hmac-sha256".into(),
            "sha256:not-a-number:AAAA:AAAA".into(),
            ParseErrorKind::InvalidCharacter,
        ),
        (
            "django-pbkdf2-sha256".into(),
            "pbkdf2_sha256$1000$x$!!!".into(),
            ParseErrorKind::InvalidBase64,
        ),
        (
            "passlib-pbkdf2-sha256".into(),
            "$pbkdf2-sha256$1000$salt".into(),
            ParseErrorKind::InvalidLength,
        ),
        (
            "atlassian-pbkdf2-sha1".into(),
            "{PKCS5S2}AAAA".into(),
            ParseErrorKind::InvalidLength,
        ),
        (
            "sha1crypt".into(),
            "$sha1$1000$salt$short".into(),
            ParseErrorKind::InvalidLength,
        ),
        (
            "drupal7".into(),
            "$S$short".into(),
            ParseErrorKind::InvalidLength,
        ),
        (
            "macos-pbkdf2-sha512".into(),
            "$ml$1000$abcd$abcd".into(),
            ParseErrorKind::InvalidLength,
        ),
        (
            "web2py-pbkdf2-sha512".into(),
            "pbkdf2(1000,20,sha1)$salt$abcd".into(),
            ParseErrorKind::InvalidCharacter,
        ),
        (
            "crc32".into(),
            "abcd:00000000".into(),
            ParseErrorKind::InvalidLength,
        ),
        (
            "siphash".into(),
            "00:2".into(),
            ParseErrorKind::InvalidLength,
        ),
        (
            "hmac-ripemd160-pass".into(),
            "abcd:key".into(),
            ParseErrorKind::InvalidLength,
        ),
        (
            "salted-sha224".into(),
            "abcd".into(),
            ParseErrorKind::InvalidCharacter,
        ),
        (
            "fortigate256".into(),
            "SH2AAAA".into(),
            ParseErrorKind::InvalidLength,
        ),
        (
            "qnx7-sha512".into(),
            "@S@abcd@abcd".into(),
            ParseErrorKind::InvalidLength,
        ),
        (
            "postgres-cram-md5".into(),
            "$postgres$user*1234*abcd".into(),
            ParseErrorKind::InvalidLength,
        ),
        (
            "mysql-cram-sha1".into(),
            "$mysqlna$notdecimal*abcd".into(),
            ParseErrorKind::InvalidCharacter,
        ),
        (
            "tacacs-plus".into(),
            "$tacacs-plus$x$00$00$00".into(),
            ParseErrorKind::InvalidCharacter,
        ),
        (
            "pop3-apop".into(),
            "$apop$challenge$abcd".into(),
            ParseErrorKind::InvalidLength,
        ),
        (
            "sasl-digest-md5".into(),
            "$sasl$too$few".into(),
            ParseErrorKind::InvalidLength,
        ),
        (
            "ospf-md5".into(),
            "$netmd5$abcd$abcd".into(),
            ParseErrorKind::InvalidLength,
        ),
        (
            "mysql-caching-sha2".into(),
            "$mysqlsha2$abcd*abcd".into(),
            ParseErrorKind::InvalidLength,
        ),
        (
            "coldfusion10".into(),
            "abcd:00".into(),
            ParseErrorKind::InvalidLength,
        ),
        (
            "des-plaintext".into(),
            "abcd:00".into(),
            ParseErrorKind::InvalidLength,
        ),
        (
            "aes128-ecb-nokdf".into(),
            "abcd:00".into(),
            ParseErrorKind::InvalidLength,
        ),
        (
            "murmurhash64a".into(),
            "1234567890abcdef:nothex".into(),
            ParseErrorKind::InvalidLength,
        ),
        (
            "sha1-cx".into(),
            "abcd:00".into(),
            ParseErrorKind::InvalidLength,
        ),
        (
            "krb5pa17".into(),
            "$krb5pa$17$user$realm".into(),
            ParseErrorKind::InvalidLength,
        ),
        (
            "krb5db17".into(),
            "$krb5db$17$user$realm$abcd".into(),
            ParseErrorKind::InvalidLength,
        ),
        (
            "krb5db-old".into(),
            "$krb5db$9$user$realm$0011223344556677".into(),
            ParseErrorKind::InvalidCharacter,
        ),
        (
            "krb5tgs23".into(),
            "$krb5tgs$23$user$realm$00$00".into(),
            ParseErrorKind::InvalidCharacter,
        ),
        (
            "krb5asrep3".into(),
            "$krb5asrep$3$user$realm$abcd$abcd".into(),
            ParseErrorKind::InvalidLength,
        ),
        (
            "sspr-md5".into(),
            "$sspr$0$100000$NONE$abcd".into(),
            ParseErrorKind::InvalidLength,
        ),
        (
            "sspr-sha1-salt".into(),
            "$sspr$2$abc$salt$abcd".into(),
            ParseErrorKind::InvalidCharacter,
        ),
        (
            "sspr-pbkdf2-sha256".into(),
            "$pbkdf2-sha256$abc$salt$digest".into(),
            ParseErrorKind::InvalidCharacter,
        ),
        (
            "sspr-pbkdf2-sha512".into(),
            "$pbkdf2-hmac-sha512$1000.salt".into(),
            ParseErrorKind::InvalidLength,
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

    let ntlm = omniex::types::Ntlm::parse("b4b9b02e6f09a9bd760f388b67351e2b", &opts).unwrap();
    assert_eq!(ntlm.digest.len(), 16);

    let dcc =
        omniex::types::Dcc::parse("c896b3c6963e03c86ade3a38370bbb09:54161084332", &opts).unwrap();
    assert_eq!(dcc.username, "54161084332");

    let sha224 = omniex::types::Sha224::parse(
        "e4fa1555ad877bf0ec455483371867200eee89550a93eff2f95a6198",
        &opts,
    )
    .unwrap();
    assert_eq!(sha224.digest.len(), 28);

    let sha256 = omniex::types::Sha256::parse(
        "127e6fbfe24a750e72930c220a8e138275656b8e5d8f48a98c3c92df2caba935",
        &opts,
    )
    .unwrap();
    assert_eq!(sha256.digest.len(), 32);

    let sha512 = omniex::types::Sha512::parse(
        "82a9dda829eb7f8ffe9fbe49e45d47d2dad9664fbb7adf72492e3c81ebd3e29134d9bc12212bf83c6840f10e8246b9db54a4859b7ccd0123d86e5872c1e5082f",
        &opts,
    )
    .unwrap();
    assert_eq!(sha512.digest.len(), 64);

    let hmail = omniex::types::HmailServer::parse(
        "8fe7ca27a17adc337cd892b1d959b4e487b8f0ef09e32214f44fb1b07e461c532e9ec3",
        &opts,
    )
    .unwrap();
    assert_eq!(&hmail.salt, b"8fe7ca");

    let descrypt = omniex::types::DesCrypt::parse("24leDr0hHfb3A", &opts).unwrap();
    assert_eq!(descrypt.crypt, "24leDr0hHfb3A");

    let apr1 = omniex::types::Apr1::parse("$apr1$62722340$zGjeAwVP2KwY6MtumUI1N/", &opts).unwrap();
    assert_eq!(apr1.salt, "62722340");
    assert_eq!(apr1.digest, "zGjeAwVP2KwY6MtumUI1N/");

    let sha512crypt = omniex::types::Sha512Crypt::parse(
        "$6$72820166$U4DVzpcYxgw7MVVDGGvB2/H5lRistD5.Ah4upwENR5UtffLR4X4SxSzfREv8z6wVl0jRFX40/KnYVvK4829kD1",
        &opts,
    )
    .unwrap();
    assert_eq!(sha512crypt.salt, "72820166");
    assert_eq!(sha512crypt.digest.len(), 86);

    let episerver_net4 = omniex::types::EpiserverNet4::parse(
        "$episerver$*1*NDg1NTIz*8BFCg/YJBAuZs/wjbH3OWKe69BLr5Lao26ybpnD48Zk",
        &opts,
    )
    .unwrap();
    assert_eq!(episerver_net4.salt, b"485523");
    assert_eq!(episerver_net4.digest.len(), 32);

    let ssha256 = omniex::types::LdapSsha256::parse(
        "{SSHA256}L5Wk0zPY2lmoR5pH20zngq37KkxFwgTquEhx95rxfVk3Ng==",
        &opts,
    )
    .unwrap();
    assert_eq!(ssha256.digest.len(), 32);

    let ssha512 = omniex::types::LdapSsha512::parse(
        "{SSHA512}Bz8w5q6qEtB1Nnc8b1jfTvTXVTwohWag33oghQGOtLChnkZTw/cuJaHQlLJEI3AWKZGCRyLA6Phujdxo+is7AjA2MDcyNjY1Mg==",
        &opts,
    )
    .unwrap();
    assert_eq!(ssha512.digest.len(), 64);

    let macos512 = omniex::types::MacosSha512::parse(
        "07543781b07e905f6f947db8ae305c248b9e12f509b41097e852e2f450e824790e677ea7397b8a9a552b1c19ecf6a6e1dd3844fa5ee5db23976962859676f7d2fb85ca94",
        &opts,
    )
    .unwrap();
    assert_eq!(omniex::format::hex(macos512.salt), "07543781");

    let mssql12 = omniex::types::Mssql2012::parse(
        "0x02003788006711b2e74e7d8cb4be96b1d187c962c5591a02d5a6ae81b3a4a094b26b7877958b26733e45016d929a756ed30d0a5ee65d3ce1970f9b7bf946e705c595f07625b1",
        &opts,
    )
    .unwrap();
    assert_eq!(omniex::format::hex(mssql12.salt), "37880067");

    let dcc2 =
        omniex::types::Dcc2::parse("$DCC2$10240#6848#e2829c8af2232fa53797e2f0e35e4626", &opts)
            .unwrap();
    assert_eq!(dcc2.iterations, 10240);
    assert_eq!(dcc2.username, "6848");

    let pix = omniex::types::CiscoPix::parse("dRRVnUmUHXOTt9nk", &opts).unwrap();
    assert_eq!(pix.crypt, "dRRVnUmUHXOTt9nk");

    let asa = omniex::types::CiscoAsa::parse("YjDBNr.A0AN7DA8s:4684", &opts).unwrap();
    assert_eq!(asa.salt, "4684");

    let phps = omniex::types::Phps::parse(
        "$PHPS$30353031383437363132$f02b0b2f25e5754edb04522c346ba243",
        &opts,
    )
    .unwrap();
    assert_eq!(phps.salt, "30353031383437363132");
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
            let first = parsed.render(&RenderOptions::default()).unwrap();
            let reparsed = registry::parse(descriptor, &first, &ParseOptions::default()).unwrap();
            assert_eq!(reparsed.render(&RenderOptions::default()).unwrap(), first);
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

    let sha256 = omniex::types::SaltedSha256::parse(
        &format!("{}:{}", "0".repeat(64), "a".repeat(30)),
        &opts,
    )
    .unwrap();
    assert!(sha256.modes().contains(&omniex::Mode::Hashcat(1410)));
    assert!(!sha256.modes().contains(&omniex::Mode::Hashcat(1430)));

    let sha512 = omniex::types::SaltedSha512::parse(
        &format!("{}:{}", "0".repeat(128), "a".repeat(30)),
        &opts,
    )
    .unwrap();
    assert!(sha512.modes().contains(&omniex::Mode::Hashcat(1710)));
    assert!(!sha512.modes().contains(&omniex::Mode::Hashcat(1730)));

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

#[test]
fn parsers_never_panic_on_generated_unicode_and_punctuation() {
    const ALPHABET: &[char] = &[
        ':',
        '$',
        '*',
        '{',
        '}',
        '0',
        'a',
        'F',
        '-',
        ' ',
        '\n',
        '\u{00e9}',
        '\u{20ac}',
        '\u{1f600}',
    ];
    let mut state = 0x9e37_79b9_u32;

    for length in 0..80 {
        let mut input = String::new();
        for _ in 0..length {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            input.push(ALPHABET[(state as usize) % ALPHABET.len()]);
        }
        for descriptor in registry::all() {
            if let Err(error) = registry::parse(descriptor, &input, &ParseOptions::default()) {
                assert!(
                    error.offset <= input.len(),
                    "`{}` reported an out-of-range offset for `{input}`",
                    descriptor.slug
                );
            }
        }
    }
}

#[test]
fn netntlm_and_ike_parsers_require_all_fields() {
    let cases = [
        ("netntlmv1", "user:domain:00:00:00"),
        ("netntlmv2", "user:domain:00:00:00"),
        ("ike-psk-md5", "00:00:00:00:00:00:00:00"),
        ("ike-psk-sha1", "00:00:00:00:00:00:00:00"),
    ];
    for (slug, input) in cases {
        let descriptor = registry::by_slug(slug).expect("registered");
        assert!(
            registry::parse(descriptor, input, &ParseOptions::default()).is_err(),
            "`{slug}` accepted an incomplete value"
        );
    }
}

#[test]
fn bcrypt_rejects_malformed_encodings_without_panicking() {
    let opts = ParseOptions::default();
    let valid = "$2a$05$MBCzKhG1KhezLh.0LRa0Kuw12nLJtpHy6DIaU.JAnqJUDYspHC.Ou";
    assert!(omniex::types::Bcrypt::parse(valid, &opts).is_ok());

    let mut wrong_separator = valid.to_owned();
    wrong_separator.replace_range(6..7, "X");
    let mut bad_cost = valid.to_owned();
    bad_cost.replace_range(4..6, "03");
    let mut bad_alphabet = valid.to_owned();
    bad_alphabet.replace_range(7..8, "!");
    let mut bad_padding = valid.to_owned();
    bad_padding.replace_range(59..60, "A");
    let mut multibyte = "é".repeat(30);

    for input in [
        &wrong_separator,
        &bad_cost,
        &bad_alphabet,
        &bad_padding,
        &multibyte,
    ] {
        assert!(
            omniex::types::Bcrypt::parse(input, &opts).is_err(),
            "accepted `{input}`"
        );
    }

    multibyte.truncate(58);
    multibyte.push('é');
    assert!(omniex::types::Bcrypt::parse(&multibyte, &opts).is_err());
}

#[test]
fn unicode_salts_use_byte_lengths_for_mode_limits() {
    let opts = ParseOptions::default();
    let digest = "0".repeat(32);
    let salt = format!("{}é", "a".repeat(27));
    let value = SaltedMd5::parse(&format!("{digest}:{salt}"), &opts).unwrap();
    assert!(!value.modes().contains(&omniex::Mode::Hashcat(30)));
    assert!(!value.modes().contains(&omniex::Mode::Hashcat(40)));
    assert!(value.modes().contains(&omniex::Mode::Hashcat(10)));
}

#[test]
fn digest_only_types_reject_invalid_input() {
    for slug in [
        "ripemd-160",
        "whirlpool",
        "gost",
        "md2",
        "sha0",
        "tiger",
        "skein-512-512",
        "md6-512",
    ] {
        let descriptor = registry::by_slug(slug).expect("registered");
        for input in ["", "abc", "zz"] {
            assert!(
                registry::parse(descriptor, input, &ParseOptions::default()).is_err(),
                "`{slug}` accepted `{input}`"
            );
        }
    }
}
