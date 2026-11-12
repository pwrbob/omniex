//! AS/400 DES, rendered as a salted DES crypt hash.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// AS/400 DES password hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "AS/400 DES",
    slug = "as400-des",
    hashcat = [8501],
    john = ["as400-des"],
)]
pub struct As400Des {
    /// Salt
    #[field(role = salt, encoding = ascii)]
    pub salt: String,

    /// 8-byte digest
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 8],
}

impl Parse for As400Des {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        if let Some(rest) = input.strip_prefix("$as400des$") {
            let fields = parse::split_fields(rest, '*', 2)?;
            return Ok(Self {
                salt: fields[0].0.to_owned(),
                digest: parse::decode_hex_field::<8>(fields[1].0, fields[1].1, "digest")?,
            });
        }
        let rest = parse::strip_prefix(input, "$as400$des$*", 0)?;
        let (salt, digest, digest_offset) = parse::split_once(rest, '*', 12)?;
        if salt.len() > 8 {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                12,
                "AS/400 DES salt must be at most eight characters",
            ));
        }
        Ok(Self {
            salt: salt.to_owned(),
            digest: parse::decode_hex_field::<8>(digest, 12 + digest_offset, "digest")?,
        })
    }
}

impl Render for As400Des {
    fn render_value(&self, opts: &RenderOptions) -> String {
        if opts.tool == crate::Tool::John {
            return format!(
                "$as400des${}*{}",
                self.salt,
                crate::format::hex(self.digest).to_uppercase()
            );
        }
        format!(
            "$as400$des$*{}*{}",
            self.salt,
            crate::format::hex(self.digest).to_uppercase()
        )
    }
}
