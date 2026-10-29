//! LDAP `{SSHA512}` SHA-512 with a salt, rendered as standard base64.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// LDAP salted SHA-512 (`{SSHA512}`) hash.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "LDAP SSHA512 (Base64)",
    slug = "ldap-ssha512",
    hashcat = [1711],
    john = ["SSHA512"],
)]
pub struct LdapSsha512 {
    /// The 64-byte SHA-512 digest.
    #[field(role = digest, encoding = base64)]
    pub digest: [u8; 64],

    /// Salt appended after the digest.
    #[field(role = salt, encoding = ascii)]
    pub salt: Vec<u8>,
}

impl Parse for LdapSsha512 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }

        let payload = input
            .strip_prefix("{SSHA512}")
            .or_else(|| input.strip_prefix("{ssha512}"))
            .ok_or_else(|| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    0,
                    "expected `{SSHA512}` prefix",
                )
            })?;
        let decoded = parse::decode_base64(payload, 9)?;

        if decoded.len() < 64 {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                9,
                "SSHA512 value must decode to at least 64 bytes",
            ));
        }

        let (digest, salt) = decoded.split_at(64);
        Ok(Self {
            digest: digest.try_into().expect("64-byte split"),
            salt: salt.to_vec(),
        })
    }
}

impl Render for LdapSsha512 {
    fn render(&self, _opts: &RenderOptions) -> String {
        let mut bytes = Vec::with_capacity(64 + self.salt.len());
        bytes.extend_from_slice(&self.digest);
        bytes.extend_from_slice(&self.salt);
        format!("{{SSHA512}}{}", crate::format::base64(bytes))
    }
}
