//! Amazon AWS Signature Version 4, rendered as a `$AWS-Sig-v4$` field sequence.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Amazon AWS Signature Version 4 values.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "Amazon AWS Signature Version 4",
    slug = "aws-sigv4",
    hashcat = [28700],
)]
pub struct AwsSigv4 {
    /// Format version.
    #[field(role = other, encoding = decimal)]
    pub version: u8,

    /// Request timestamp.
    #[field(role = other, encoding = ascii)]
    pub timestamp: String,

    /// AWS region.
    #[field(role = other, encoding = ascii)]
    pub region: String,

    /// AWS service name.
    #[field(role = other, encoding = ascii)]
    pub service: String,

    /// The 32-byte signing key.
    #[field(role = key, encoding = hex)]
    pub key: [u8; 32],

    /// The 32-byte signature.
    #[field(role = digest, encoding = hex)]
    pub signature: [u8; 32],
}

impl Parse for AwsSigv4 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$AWS-Sig-v4$", 0)?;
        let fields = parse::split_fields(rest, '$', 6)?;
        Ok(Self {
            version: fields[0].0.parse::<u8>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    12,
                    "invalid AWS signature version",
                )
            })?,
            timestamp: fields[1].0.to_owned(),
            region: fields[2].0.to_owned(),
            service: fields[3].0.to_owned(),
            key: parse::decode_hex_field::<32>(fields[4].0, fields[4].1, "key")?,
            signature: parse::decode_hex_field::<32>(fields[5].0, fields[5].1, "signature")?,
        })
    }
}

impl Render for AwsSigv4 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$AWS-Sig-v4${}${}${}${}${}${}",
            self.version,
            self.timestamp,
            self.region,
            self.service,
            crate::format::hex(self.key),
            crate::format::hex(self.signature)
        )
    }
}
