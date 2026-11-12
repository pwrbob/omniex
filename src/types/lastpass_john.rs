//! John LastPass hashes, rendered as `$lastpass$<email>$<iterations>$<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// LastPass hashes in the John serialization.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "LastPass legacy",
    slug = "lastpass-legacy",
    hashcat = [],
    john = ["LastPass"]
)]
pub struct LastpassJohn {
    /// Account e-mail
    #[field(role = username, encoding = ascii)]
    pub email: String,

    /// Iteration count
    #[field(role = iterations, encoding = decimal)]
    pub iterations: u32,

    /// Digest
    #[field(role = digest, encoding = base64)]
    pub digest: Vec<u8>,
}

impl Parse for LastpassJohn {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$lastpass$", 0)?;
        let fields = parse::split_fields(rest, '$', 3)?;
        Ok(Self {
            email: fields[0].0.to_owned(),
            iterations: fields[1].0.parse::<u32>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    fields[1].1,
                    "invalid LastPass iteration count",
                )
            })?,
            digest: parse::decode_base64(fields[2].0, fields[2].1)?,
        })
    }
}

impl Render for LastpassJohn {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$lastpass${}${}${}",
            self.email,
            self.iterations,
            crate::format::base64(&self.digest)
        )
    }
}
