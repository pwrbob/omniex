//! ChaCha20 known-plaintext hashes, rendered as
//! `$chacha20$*<position>*<offset>*<iv>*<plaintext>*<ciphertext>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// ChaCha20 known-plaintext hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "ChaCha20", slug = "chacha20", hashcat = [15400])]
pub struct ChaCha20 {
    /// Eight-byte counter position.
    #[field(role = other, encoding = hex)]
    pub position: [u8; 8],

    /// Key offset from 0 to 63.
    #[field(role = other, encoding = decimal)]
    pub offset: u8,

    /// Eight-byte initialization vector.
    #[field(role = salt, encoding = hex)]
    pub iv: [u8; 8],

    /// Eight bytes of known plaintext.
    #[field(role = other, encoding = hex)]
    pub plaintext: [u8; 8],

    /// Eight bytes of ciphertext.
    #[field(role = digest, encoding = hex)]
    pub ciphertext: [u8; 8],
}

impl Parse for ChaCha20 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$chacha20$*", 0)?;
        let fields = parse::split_fields(rest, '*', 5)?;
        let offset = fields[1].0.parse::<u8>().map_err(|_| {
            parse::error(
                ParseErrorKind::InvalidCharacter,
                11,
                "invalid ChaCha20 offset",
            )
        })?;
        if offset > 63 {
            return Err(parse::error(
                ParseErrorKind::InvalidCharacter,
                11,
                "ChaCha20 offsets are at most 63",
            ));
        }
        Ok(Self {
            position: parse::decode_hex_field::<8>(fields[0].0, fields[0].1, "position")?,
            offset,
            iv: parse::decode_hex_field::<8>(fields[2].0, fields[2].1, "iv")?,
            plaintext: parse::decode_hex_field::<8>(fields[3].0, fields[3].1, "plaintext")?,
            ciphertext: parse::decode_hex_field::<8>(fields[4].0, fields[4].1, "ciphertext")?,
        })
    }
}

impl Render for ChaCha20 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$chacha20$*{}*{}*{}*{}*{}",
            crate::format::hex(self.position),
            self.offset,
            crate::format::hex(self.iv),
            crate::format::hex(self.plaintext),
            crate::format::hex(self.ciphertext)
        )
    }
}
