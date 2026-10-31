//! Veeam backup hashes, rendered as `$vbk$*<data>*<iterations>*<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Veeam VBK backup hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "Veeam VBK", slug = "veeam", hashcat = [31200])]
pub struct Veeam {
    /// Encrypted data as a decimal string.
    #[field(role = ciphertext, encoding = ascii)]
    pub data: String,

    /// Iteration count.
    #[field(role = iterations, encoding = decimal)]
    pub iterations: u32,

    /// Sixteen-byte digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 16],
}

impl Parse for Veeam {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$vbk$*", 0)?;
        let fields = parse::split_fields(rest, '*', 3)?;
        let iterations = fields[1].0.parse::<u32>().map_err(|_| {
            parse::error(
                ParseErrorKind::InvalidCharacter,
                fields[1].1,
                "invalid Veeam iteration count",
            )
        })?;
        Ok(Self {
            data: fields[0].0.to_owned(),
            iterations,
            digest: parse::decode_hex_field::<16>(fields[2].0, fields[2].1, "digest")?,
        })
    }
}

impl Render for Veeam {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$vbk$*{}*{}*{}",
            self.data,
            self.iterations,
            crate::format::hex(self.digest)
        )
    }
}
