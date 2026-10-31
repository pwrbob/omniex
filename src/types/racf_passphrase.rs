//! RACF DES passphrase hashes, rendered as `<user>*<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// RACF DES passphrase hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "RACF DES Passphrase",
    slug = "racf-passphrase",
    hashcat = [37400]
)]
pub struct RacfPassphrase {
    /// RACF user name.
    #[field(role = username, encoding = ascii)]
    pub user: String,

    /// Digest bytes.
    #[field(role = digest, encoding = hex)]
    pub digest: Vec<u8>,
}

impl Parse for RacfPassphrase {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let (user, digest, digest_offset) = parse::split_once(input, '*', 0)?;
        Ok(Self {
            user: user.to_owned(),
            digest: parse::decode_hex(digest, digest_offset)?,
        })
    }
}

impl Render for RacfPassphrase {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "{}*{}",
            self.user,
            crate::format::hex(&self.digest).to_uppercase()
        )
    }
}
