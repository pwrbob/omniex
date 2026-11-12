//! Iterated-SHA1 hashes, rendered as `$sisha1$<iterations>$<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Iterated-SHA1 hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "Iterated-SHA1",
    slug = "iterated-sha1",
    hashcat = [],
    john = ["Iterated-SHA1"]
)]
pub struct IteratedSha1 {
    /// Iteration count
    #[field(role = iterations, encoding = decimal)]
    pub iterations: u32,

    /// Hexadecimal digest
    #[field(role = digest, encoding = ascii)]
    pub digest: String,
}

impl Parse for IteratedSha1 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$sisha1$", 0)?;
        let (iterations, digest, digest_offset) = parse::split_once(rest, '$', 8)?;
        Ok(Self {
            iterations: iterations.parse::<u32>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    8,
                    "invalid Iterated-SHA1 iteration count",
                )
            })?,
            digest: {
                if digest.is_empty() {
                    return Err(parse::error(
                        ParseErrorKind::InvalidLength,
                        digest_offset,
                        "missing Iterated-SHA1 digest",
                    ));
                }
                digest.to_owned()
            },
        })
    }
}

impl Render for IteratedSha1 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("$sisha1${}${}", self.iterations, self.digest)
    }
}
