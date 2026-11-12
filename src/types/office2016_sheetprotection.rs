//! MS Office 2016 SheetProtection, rendered as `$office$2016$0$<spins>$<salt>$<hash>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// MS Office 2016 sheet protection hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "MS Office 2016 - SheetProtection",
    slug = "office2016-sheetprotection",
    hashcat = [25300],
)]
pub struct Office2016Sheetprotection {
    /// Spin count
    #[field(role = iterations, encoding = decimal)]
    pub spin_count: u32,

    /// 16-byte salt
    #[field(role = salt, encoding = base64)]
    pub salt: [u8; 16],

    /// 64-byte hash
    #[field(role = digest, encoding = base64)]
    pub digest: [u8; 64],
}

impl Parse for Office2016Sheetprotection {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$office$2016$0$", 0)?;
        let fields = parse::split_fields(rest, '$', 3)?;
        let salt = parse::decode_base64(fields[1].0, fields[1].1)?;
        let digest = parse::decode_base64(fields[2].0, fields[2].1)?;
        let salt = salt.as_slice().try_into().map_err(|_| {
            parse::error(
                ParseErrorKind::InvalidLength,
                fields[1].1,
                "Office salt must be 16 bytes",
            )
        })?;
        let digest = digest.as_slice().try_into().map_err(|_| {
            parse::error(
                ParseErrorKind::InvalidLength,
                fields[2].1,
                "Office hash must be 64 bytes",
            )
        })?;
        Ok(Self {
            spin_count: fields[0].0.parse::<u32>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    15,
                    "invalid Office spin count",
                )
            })?,
            salt,
            digest,
        })
    }
}

impl Render for Office2016Sheetprotection {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$office$2016$0${}${}${}",
            self.spin_count,
            crate::format::base64(self.salt),
            crate::format::base64(self.digest)
        )
    }
}
