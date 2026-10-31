//! SAP CODVN B hashes, rendered as `<user>$<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// SAP CODVN B (BCODE) hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "SAP CODVN B",
    slug = "sap-bcode",
    hashcat = [7700, 7701],
    modes_fn = sap_bcode_modes,
)]
pub struct SapBcode {
    /// SAP user name.
    #[field(role = salt, encoding = ascii)]
    pub user: String,

    /// Eight-byte digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 8],
}

pub fn sap_bcode_modes(value: &SapBcode) -> Vec<crate::Mode> {
    if value.digest[4..] == [0, 0, 0, 0] {
        vec![crate::Mode::Hashcat(7701)]
    } else {
        vec![crate::Mode::Hashcat(7700)]
    }
}

impl Parse for SapBcode {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let (user, rest, rest_offset) = parse::split_once(input, '$', 0)?;
        if user.is_empty() || user.len() > 40 {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                0,
                "SAP user names are between 1 and 40 characters",
            ));
        }
        Ok(Self {
            user: user.to_owned(),
            digest: parse::decode_hex_field::<8>(rest, rest_offset, "digest")?,
        })
    }
}

impl Render for SapBcode {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "{}${}",
            self.user,
            crate::format::hex(self.digest).to_uppercase()
        )
    }
}
