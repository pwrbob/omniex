//! MSSQL 2025 password hashes, rendered as a `0x0300` hexadecimal blob.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// MSSQL 2025 password hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "MSSQL (2025)", slug = "mssql-2025", hashcat = [36601])]
pub struct Mssql2025 {
    /// Hash payload.
    #[field(role = digest, encoding = hex)]
    pub payload: Vec<u8>,
}

impl Parse for Mssql2025 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "0x0300", 0)?;
        Ok(Self {
            payload: parse::decode_hex(rest, 6)?,
        })
    }
}

impl Render for Mssql2025 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("0x0300{}", crate::format::hex(&self.payload).to_uppercase())
    }
}
