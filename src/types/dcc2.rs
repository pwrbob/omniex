//! Domain Cached Credentials 2, rendered as `$DCC2$<iterations>#<username>#<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// MS Cache 2 (Domain Cached Credentials 2) hash.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "Domain Cached Credentials 2",
    slug = "dcc2",
    hashcat = [2100],
    john = ["mscash2"],
)]
pub struct Dcc2 {
    /// Iteration count.
    #[field(role = iterations, encoding = decimal)]
    pub iterations: u32,

    /// User name, serialized as ASCII.
    #[field(role = username, encoding = ascii)]
    pub username: String,

    /// The 16-byte digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 16],
}

impl Parse for Dcc2 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }

        let rest = parse::strip_prefix(input, "$DCC2$", 0)?;
        let (iterations, rest, rest_offset) = parse::split_once(rest, '#', 6)?;
        let iterations = iterations.parse::<u32>().map_err(|_| {
            parse::error(
                ParseErrorKind::InvalidCharacter,
                6,
                "invalid DCC2 iteration count",
            )
        })?;
        let (username, digest, digest_offset) = parse::split_once(rest, '#', rest_offset)?;

        Ok(Self {
            iterations,
            username: username.to_owned(),
            digest: parse::decode_hex_field::<16>(digest, digest_offset, "digest")?,
        })
    }
}

impl Render for Dcc2 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$DCC2${}#{}#{}",
            self.iterations,
            self.username,
            crate::format::hex(self.digest)
        )
    }
}
