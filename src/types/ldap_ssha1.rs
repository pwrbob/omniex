//! LDAP `{SSHA}` SHA-1 with a salt, rendered as standard base64.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// LDAP salted SHA-1 (`{SSHA}`) hash.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "LDAP SSHA1 (Base64)",
    slug = "ldap-ssha1",
    hashcat = [111],
    john = ["Salted-SHA1"],
)]
pub struct LdapSsha1 {
    /// 20-byte SHA-1 digest
    #[field(role = digest, encoding = base64)]
    pub digest: [u8; 20],

    /// Salt after digest
    #[field(role = salt, encoding = ascii)]
    pub salt: Vec<u8>,
}

impl Parse for LdapSsha1 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }

        let payload = input
            .strip_prefix("{SSHA}")
            .or_else(|| input.strip_prefix("{ssha}"))
            .ok_or_else(|| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    0,
                    "expected `{SSHA}` prefix",
                )
            })?;
        let decoded = parse::decode_base64(payload, 6)?;

        if decoded.len() < 20 {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                6,
                "SSHA value must decode to at least 20 bytes",
            ));
        }

        let (digest, salt) = decoded.split_at(20);
        let digest = digest.try_into().expect("20-byte split");

        Ok(Self {
            digest,
            salt: salt.to_vec(),
        })
    }
}

impl Render for LdapSsha1 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        let mut bytes = Vec::with_capacity(20 + self.salt.len());
        bytes.extend_from_slice(&self.digest);
        bytes.extend_from_slice(&self.salt);
        format!("{{SSHA}}{}", crate::format::base64(bytes))
    }
}
