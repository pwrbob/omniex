//! Atlassian PBKDF2-HMAC-SHA1, rendered as `{PKCS5S2}<base64>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Atlassian PBKDF2-HMAC-SHA1 hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "Atlassian (PBKDF2-HMAC-SHA1)",
    slug = "atlassian-pbkdf2-sha1",
    hashcat = [40033],
)]
pub struct AtlassianPbkdf2Sha1 {
    /// The 16-byte salt.
    #[field(role = salt, encoding = hex)]
    pub salt: [u8; 16],

    /// The 32-byte digest block.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 32],
}

impl Parse for AtlassianPbkdf2Sha1 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }

        let encoded = parse::strip_prefix(input, "{PKCS5S2}", 0)?;
        let decoded = parse::decode_base64(encoded, 9)?;
        if decoded.len() != 48 {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                9,
                "Atlassian value must decode to 48 bytes",
            ));
        }

        let mut salt = [0u8; 16];
        let mut digest = [0u8; 32];
        salt.copy_from_slice(&decoded[..16]);
        digest.copy_from_slice(&decoded[16..]);

        Ok(Self { salt, digest })
    }
}

impl Render for AtlassianPbkdf2Sha1 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        let mut bytes = Vec::with_capacity(48);
        bytes.extend_from_slice(&self.salt);
        bytes.extend_from_slice(&self.digest);
        format!("{{PKCS5S2}}{}", crate::format::base64(bytes))
    }
}
