//! iClass key recovery hashes, rendered as a `$iclass$` field sequence.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// iClass key recovery hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "iClass",
    slug = "iclass",
    hashcat = [36900, 36901],
    modes_fn = iclass_modes,
)]
pub struct Iclass {
    /// Scheme name (`iclass`/`iclass_leg`)
    #[field(role = other, encoding = ascii)]
    pub scheme: String,

    /// 8-byte key
    #[field(role = key, encoding = ascii)]
    pub key: String,

    /// First block data
    #[field(role = other, encoding = ascii)]
    pub block1: String,

    /// First MAC
    #[field(role = digest, encoding = ascii)]
    pub mac1: String,

    /// Second block data
    #[field(role = other, encoding = ascii)]
    pub block2: String,

    /// Second MAC
    #[field(role = other, encoding = ascii)]
    pub mac2: String,
}

pub fn iclass_modes(value: &Iclass) -> Vec<crate::Mode> {
    match value.scheme.as_str() {
        "iclass" => vec![crate::Mode::Hashcat(36900)],
        "iclass_leg" => vec![crate::Mode::Hashcat(36901)],
        _ => Vec::new(),
    }
}

impl Parse for Iclass {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$", 0)?;
        let (scheme, rest, _) = parse::split_once(rest, '$', 1)?;
        if !matches!(scheme, "iclass" | "iclass_leg") {
            return Err(parse::error(
                ParseErrorKind::InvalidCharacter,
                1,
                "expected an iClass scheme",
            ));
        }
        let fields = parse::split_fields(rest, '$', 5)?;
        Ok(Self {
            scheme: scheme.to_owned(),
            key: fields[0].0.to_owned(),
            block1: fields[1].0.to_owned(),
            mac1: fields[2].0.to_owned(),
            block2: fields[3].0.to_owned(),
            mac2: fields[4].0.to_owned(),
        })
    }
}

impl Render for Iclass {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "${}${}${}${}${}${}",
            self.scheme, self.key, self.block1, self.mac1, self.block2, self.mac2
        )
    }
}
