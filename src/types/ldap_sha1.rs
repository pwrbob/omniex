//! LDAP `{SHA}` SHA-1, rendered as standard base64.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// LDAP SHA-1 (`{SHA}`) hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, HashType)]
#[hash(
    name = "LDAP SHA1 (Base64)",
    slug = "ldap-sha1",
    hashcat = [101],
)]
pub struct LdapSha1 {
    /// The 20-byte SHA-1 digest.
    #[field(role = digest, encoding = base64)]
    pub digest: [u8; 20],
}

impl Parse for LdapSha1 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }

        let payload = input
            .strip_prefix("{SHA}")
            .or_else(|| input.strip_prefix("{sha}"))
            .ok_or_else(|| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    0,
                    "expected `{SHA}` prefix",
                )
            })?;
        let digest = parse::decode_base64(payload, 4)?;

        digest
            .try_into()
            .map(|digest| Self { digest })
            .map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidLength,
                    4,
                    "SHA1 digest must decode to 20 bytes",
                )
            })
    }
}

impl Render for LdapSha1 {
    fn render(&self, _opts: &RenderOptions) -> String {
        format!("{{SHA}}{}", crate::format::base64(self.digest))
    }
}
