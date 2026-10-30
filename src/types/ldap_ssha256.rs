//! LDAP `{SSHA256}` SHA-256 with a salt, rendered as standard base64.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// LDAP salted SHA-256 (`{SSHA256}`) hash.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "LDAP SSHA256 (Base64)",
    slug = "ldap-ssha256",
    hashcat = [1411],
)]
pub struct LdapSsha256 {
    /// The 32-byte SHA-256 digest.
    #[field(role = digest, encoding = base64)]
    pub digest: [u8; 32],

    /// Salt appended after the digest.
    #[field(role = salt, encoding = ascii)]
    pub salt: Vec<u8>,
}

impl Parse for LdapSsha256 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }

        let payload = input
            .strip_prefix("{SSHA256}")
            .or_else(|| input.strip_prefix("{ssha256}"))
            .ok_or_else(|| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    0,
                    "expected `{SSHA256}` prefix",
                )
            })?;
        let decoded = parse::decode_base64(payload, 9)?;

        if decoded.len() < 32 {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                9,
                "SSHA256 value must decode to at least 32 bytes",
            ));
        }

        let (digest, salt) = decoded.split_at(32);
        Ok(Self {
            digest: digest.try_into().expect("32-byte split"),
            salt: salt.to_vec(),
        })
    }
}

impl Render for LdapSsha256 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        let mut bytes = Vec::with_capacity(32 + self.salt.len());
        bytes.extend_from_slice(&self.digest);
        bytes.extend_from_slice(&self.salt);
        format!("{{SSHA256}}{}", crate::format::base64(bytes))
    }
}
