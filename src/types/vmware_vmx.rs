//! VMware VMX, rendered as `$vmx$<version>$<iterations>$<salt>$<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// VMware VMX hashes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, HashType)]
#[hash(
    name = "VMware VMX",
    slug = "vmware-vmx",
    hashcat = [27400],
)]
pub struct VmwareVmx {
    /// Format version.
    #[field(role = other, encoding = decimal)]
    pub version: u8,

    /// Iteration count.
    #[field(role = iterations, encoding = decimal)]
    pub iterations: u32,

    /// The 16-byte salt.
    #[field(role = salt, encoding = hex)]
    pub salt: [u8; 16],

    /// The 32-byte digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 32],
}

impl Parse for VmwareVmx {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$vmx$", 0)?;
        let fields = parse::split_fields(rest, '$', 4)?;
        Ok(Self {
            version: fields[0].0.parse::<u8>().map_err(|_| {
                parse::error(ParseErrorKind::InvalidCharacter, 5, "invalid VMX version")
            })?,
            iterations: fields[1].0.parse::<u32>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    fields[1].1,
                    "invalid VMX iteration count",
                )
            })?,
            salt: parse::decode_hex_field::<16>(fields[2].0, fields[2].1, "salt")?,
            digest: parse::decode_hex_field::<32>(fields[3].0, fields[3].1, "digest")?,
        })
    }
}

impl Render for VmwareVmx {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$vmx${}${}${}${}",
            self.version,
            self.iterations,
            crate::format::hex(self.salt),
            crate::format::hex(self.digest)
        )
    }
}
