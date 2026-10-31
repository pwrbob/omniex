//! Apple Secure Notes, rendered as `$ASN$*<version>*<iterations>*<salt>*<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Apple Secure Notes hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "Apple Secure Notes",
    slug = "apple-secure-notes",
    hashcat = [16200], john = ["notes"],
)]
pub struct AppleSecureNotes {
    /// Format version.
    #[field(role = other, encoding = decimal)]
    pub version: u32,

    /// Iteration count.
    #[field(role = iterations, encoding = decimal)]
    pub iterations: u32,

    /// ASCII salt.
    #[field(role = salt, encoding = ascii)]
    pub salt: String,

    /// The 24-byte digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 24],
}

impl Parse for AppleSecureNotes {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$ASN$*", 0)?;
        let fields = parse::split_fields(rest, '*', 4)?;
        Ok(Self {
            version: fields[0].0.parse::<u32>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    6,
                    "invalid Apple Secure Notes version",
                )
            })?,
            iterations: fields[1].0.parse::<u32>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    fields[1].1,
                    "invalid Apple Secure Notes iteration count",
                )
            })?,
            salt: fields[2].0.to_owned(),
            digest: parse::decode_hex_field::<24>(fields[3].0, fields[3].1, "digest")?,
        })
    }
}

impl Render for AppleSecureNotes {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$ASN$*{}*{}*{}*{}",
            self.version,
            self.iterations,
            self.salt,
            crate::format::hex(self.digest)
        )
    }
}
