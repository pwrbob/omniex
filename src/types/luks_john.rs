//! John LUKS hashes, rendered as `$luks$1$<size>$<header>$<af size>$<af data>$<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Inlined LUKS header in John's native serialization.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "LUKS header",
    slug = "luks-header",
    john = ["LUKS"],
)]
pub struct LuksJohn {
    /// Inline marker (must be 1)
    #[field(role = other, encoding = decimal)]
    pub inlined: u8,

    /// Raw 592-byte LUKS header
    #[field(role = salt, encoding = hex)]
    pub header: [u8; 592],

    /// Anti-forensic data length
    #[field(role = other, encoding = decimal)]
    pub af_size: u32,

    /// Anti-forensic data
    #[field(role = ciphertext, encoding = base64)]
    pub af_data: Vec<u8>,

    /// 20-byte master-key digest
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 20],
}

impl Parse for LuksJohn {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$luks$", 0)?;
        let fields = parse::split_fields(rest, '$', 6)?;
        let inlined = fields[0].0.parse::<u8>().map_err(|_| {
            parse::error(
                ParseErrorKind::InvalidCharacter,
                fields[0].1,
                "invalid LUKS inline marker",
            )
        })?;
        if inlined != 1 {
            return Err(parse::error(
                ParseErrorKind::Unsupported,
                fields[0].1,
                "only inline LUKS hashes are supported",
            ));
        }
        let header_size = fields[1].0.parse::<usize>().map_err(|_| {
            parse::error(
                ParseErrorKind::InvalidCharacter,
                fields[1].1,
                "invalid LUKS header size",
            )
        })?;
        if header_size != 592 {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                fields[1].1,
                "John LUKS header must be 592 bytes",
            ));
        }
        let af_size = fields[3].0.parse::<u32>().map_err(|_| {
            parse::error(
                ParseErrorKind::InvalidCharacter,
                fields[3].1,
                "invalid LUKS anti-forensic size",
            )
        })?;
        let af = parse::decode_base64(fields[4].0, fields[4].1)?;
        if af.len() != af_size as usize {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                fields[4].1,
                "LUKS anti-forensic data does not match its declared size",
            ));
        }
        Ok(Self {
            inlined: 1,
            header: parse::decode_hex_field::<592>(fields[2].0, fields[2].1, "header")?,
            af_size,
            af_data: af,
            digest: parse::decode_hex_field::<20>(fields[5].0, fields[5].1, "digest")?,
        })
    }
}

impl Render for LuksJohn {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$luks$1$592${}${}${}${}",
            crate::format::hex(self.header),
            self.af_size,
            crate::format::base64(&self.af_data),
            crate::format::hex(self.digest)
        )
    }
}
