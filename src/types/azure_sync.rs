//! Microsoft Azure AD Sync hashes, rendered as
//! `v1;PPH1_MD4,<object id>,<iterations>,<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Microsoft Azure AD Sync hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "MS-AzureSync", slug = "azure-sync", hashcat = [40037], john = ["AzureAD"])]
pub struct AzureSync {
    /// Object identifier
    #[field(role = username, encoding = ascii)]
    pub object_id: String,

    /// Iteration count
    #[field(role = iterations, encoding = decimal)]
    pub iterations: u32,

    /// 32-byte digest
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 32],
}

impl Parse for AzureSync {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "v1;PPH1_MD4,", 0)?.trim_end_matches(';');
        let fields = parse::split_fields(rest, ',', 3)?;
        let iterations = fields[1].0.parse::<u32>().map_err(|_| {
            parse::error(
                ParseErrorKind::InvalidCharacter,
                fields[1].1,
                "invalid Azure Sync iteration count",
            )
        })?;
        Ok(Self {
            object_id: fields[0].0.to_owned(),
            iterations,
            digest: parse::decode_hex_field::<32>(fields[2].0, fields[2].1, "digest")?,
        })
    }
}

impl Render for AzureSync {
    fn render_value(&self, opts: &RenderOptions) -> String {
        if opts.tool == crate::Tool::John {
            format!(
                "v1;PPH1_MD4,{},{},{};",
                self.object_id,
                self.iterations,
                crate::format::hex(self.digest)
            )
        } else {
            format!(
                "v1;PPH1_MD4,{},{},{}",
                self.object_id,
                self.iterations,
                crate::format::hex(self.digest)
            )
        }
    }
}
