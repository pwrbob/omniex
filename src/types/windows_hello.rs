//! Windows Hello PIN/password, rendered as a `$WINHELLO$` field sequence.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Windows Hello PIN and password hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "Windows Hello PIN/Password",
    slug = "windows-hello",
    hashcat = [28100],
)]
pub struct WindowsHello {
    /// Hash algorithm name
    #[field(role = other, encoding = ascii)]
    pub algorithm: String,

    /// Iteration count
    #[field(role = iterations, encoding = decimal)]
    pub iterations: u32,

    /// Salt
    #[field(role = salt, encoding = hex)]
    pub salt: Vec<u8>,

    /// Signature
    #[field(role = digest, encoding = hex)]
    pub signature: Vec<u8>,

    /// Master key
    #[field(role = key, encoding = hex)]
    pub master_key: Vec<u8>,

    /// HMAC
    #[field(role = other, encoding = hex)]
    pub hmac: Vec<u8>,

    /// Verification blob
    #[field(role = ciphertext, encoding = hex)]
    pub blob: Vec<u8>,

    /// Magic value
    #[field(role = other, encoding = hex)]
    pub magic: Vec<u8>,
}

impl Parse for WindowsHello {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$WINHELLO$*", 0)?;
        let fields = parse::split_fields(rest, '*', 8)?;
        Ok(Self {
            algorithm: fields[0].0.to_owned(),
            iterations: fields[1].0.parse::<u32>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    fields[1].1,
                    "invalid Windows Hello iteration count",
                )
            })?,
            salt: parse::decode_hex(fields[2].0, fields[2].1)?,
            signature: parse::decode_hex(fields[3].0, fields[3].1)?,
            master_key: parse::decode_hex(fields[4].0, fields[4].1)?,
            hmac: parse::decode_hex(fields[5].0, fields[5].1)?,
            blob: parse::decode_hex(fields[6].0, fields[6].1)?,
            magic: parse::decode_hex(fields[7].0, fields[7].1)?,
        })
    }
}

impl Render for WindowsHello {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$WINHELLO$*{}*{}*{}*{}*{}*{}*{}*{}",
            self.algorithm,
            self.iterations,
            crate::format::hex(&self.salt),
            crate::format::hex(&self.signature),
            crate::format::hex(&self.master_key),
            crate::format::hex(&self.hmac),
            crate::format::hex(&self.blob),
            crate::format::hex(&self.magic)
        )
    }
}
