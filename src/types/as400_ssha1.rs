//! AS/400 salted SHA1, rendered as `$as400$ssha1$*<user>*<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// AS/400 salted SHA1 hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "AS/400 SSHA1", slug = "as400-ssha1", hashcat = [35200])]
pub struct As400Ssha1 {
    /// AS/400 user name.
    #[field(role = salt, encoding = ascii)]
    pub user: String,

    /// Twenty-byte digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 20],
}

impl Parse for As400Ssha1 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$as400$ssha1$*", 0)?;
        let fields = parse::split_fields(rest, '*', 2)?;
        if fields[0].0.is_empty() || fields[0].0.len() > 10 {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                fields[0].1,
                "AS/400 user names are between 1 and 10 characters",
            ));
        }
        Ok(Self {
            user: fields[0].0.to_owned(),
            digest: parse::decode_hex_field::<20>(fields[1].0, fields[1].1, "digest")?,
        })
    }
}

impl Render for As400Ssha1 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$as400$ssha1$*{}*{}",
            self.user,
            crate::format::hex(self.digest).to_uppercase()
        )
    }
}
