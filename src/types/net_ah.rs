//! NetAH hashes, rendered as `$net-ah$<version>$<packet>$<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// NetAH hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "NetAH", slug = "net-ah", hashcat = [], john = ["net-ah"])]
pub struct NetAh {
    /// Version
    #[field(role = other, encoding = decimal)]
    pub version: u8,

    /// Packet data
    #[field(role = salt, encoding = ascii)]
    pub packet: String,

    /// Digest
    #[field(role = digest, encoding = ascii)]
    pub digest: String,
}

impl Parse for NetAh {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$net-ah$", 0)?;
        let fields = parse::split_fields(rest, '$', 3)?;
        Ok(Self {
            version: fields[0].0.parse::<u8>().map_err(|_| {
                parse::error(ParseErrorKind::InvalidCharacter, 8, "invalid NetAH version")
            })?,
            packet: fields[1].0.to_owned(),
            digest: fields[2].0.to_owned(),
        })
    }
}

impl Render for NetAh {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("$net-ah${}${}${}", self.version, self.packet, self.digest)
    }
}
