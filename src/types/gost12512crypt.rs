//! gost12512crypt hashes, rendered as `$gost12512hash$<salt>$<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// gost12512crypt (Unix GOST) hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "gost12512crypt",
    slug = "gost12512crypt",
    hashcat = [35600], john = ["streebog512crypt"]
)]
pub struct Gost12512crypt {
    /// Salt
    #[field(role = salt, encoding = ascii)]
    pub salt: String,

    /// Crypt base64 digest
    #[field(role = digest, encoding = ascii)]
    pub digest: String,
}

impl Parse for Gost12512crypt {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$gost12512hash$", 0)?;
        let (salt, digest, digest_offset) = parse::split_once(rest, '$', 15)?;
        if digest.is_empty() {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                digest_offset,
                "missing GOST digest",
            ));
        }
        Ok(Self {
            salt: salt.to_owned(),
            digest: digest.to_owned(),
        })
    }
}

impl Render for Gost12512crypt {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("$gost12512hash${}${}", self.salt, self.digest)
    }
}
