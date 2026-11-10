//! RAKP hashes, rendered as `$rakp$<data>$<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// RAKP hashes in the `$rakp$` serialization.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "RAKP",
    slug = "rakp",
    hashcat = [],
    john = ["RAKP-MD5", "RAKP-SHA1", "RAKP-SHA256"],
    modes_fn = rakp_modes,
)]
pub struct Rakp {
    /// Session data.
    #[field(role = salt, encoding = ascii)]
    pub data: String,

    /// Hexadecimal digest, whose length selects the mode.
    #[field(role = digest, encoding = hex)]
    pub digest: Vec<u8>,
}

pub fn rakp_modes(value: &Rakp) -> Vec<crate::Mode> {
    match value.digest.len() {
        16 => vec![crate::Mode::John("RAKP-MD5")],
        20 => vec![crate::Mode::John("RAKP-SHA1")],
        32 => vec![crate::Mode::John("RAKP-SHA256")],
        _ => Vec::new(),
    }
}

impl Parse for Rakp {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$rakp$", 0)?;
        let (data, digest, digest_offset) = parse::split_once(rest, '$', 6)?;
        let digest = parse::decode_hex(digest, digest_offset)?;
        if !matches!(digest.len(), 16 | 20 | 32) {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                digest_offset,
                "RAKP digests are 16, 20, or 32 bytes",
            ));
        }
        Ok(Self {
            data: data.to_owned(),
            digest,
        })
    }
}

impl Render for Rakp {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("$rakp${}${}", self.data, crate::format::hex(&self.digest))
    }
}
