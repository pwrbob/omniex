//! SAP CODVN F/G hashes, rendered as `<user>$<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// SAP CODVN F/G (PASSCODE) hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "SAP CODVN F/G",
    slug = "sap-passcode",
    hashcat = [7800, 7801], john = ["sapg"],
    modes_fn = sap_passcode_modes,
)]
pub struct SapPasscode {
    /// SAP user name.
    #[field(role = salt, encoding = ascii)]
    pub user: String,

    /// Twenty-byte digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 20],
}

pub fn sap_passcode_modes(value: &SapPasscode) -> Vec<crate::Mode> {
    if value.digest[12..] == [0; 8] {
        vec![crate::Mode::Hashcat(7801)]
    } else {
        vec![crate::Mode::Hashcat(7800)]
    }
}

impl Parse for SapPasscode {
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
            digest: parse::decode_hex_field::<20>(rest, rest_offset, "digest")?,
        })
    }
}

impl Render for SapPasscode {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "{}${}",
            self.user,
            crate::format::hex(self.digest).to_uppercase()
        )
    }
}
