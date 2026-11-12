//! Dahua Authentication MD5, rendered as an eight-character digest.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Dahua Authentication MD5 hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "Dahua Authentication MD5",
    slug = "dahua-md5",
    hashcat = [24900],
    john = ["dahua"],
)]
pub struct DahuaMd5 {
    /// 8-character digest
    #[field(role = digest, encoding = ascii)]
    pub digest: String,
}

impl Parse for DahuaMd5 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let input = input.strip_prefix("$dahua$").unwrap_or(input);
        if input.len() != 8 {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                input.len(),
                "Dahua Authentication MD5 digests are eight characters",
            ));
        }
        Ok(Self {
            digest: input.to_owned(),
        })
    }
}

impl Render for DahuaMd5 {
    fn render_value(&self, opts: &RenderOptions) -> String {
        if opts.tool == crate::Tool::John {
            format!("$dahua${}", self.digest)
        } else {
            self.digest.clone()
        }
    }
}
