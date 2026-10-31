//! OpenBSD softraid FDE hashes, rendered as
//! `$openbsd-softraid$<iterations or version>$<data>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// OpenBSD softraid full-disk encryption hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "OpenBSD softraid FDE",
    slug = "openbsd-softraid",
    hashcat = [38800, 38810],
    modes_fn = openbsd_softraid_modes,
)]
pub struct OpenbsdSoftraid {
    /// Iteration count for PBKDF2, or the bcrypt cost marker.
    #[field(role = other, encoding = decimal)]
    pub iterations: u32,

    /// Version-specific fields, preserved verbatim.
    #[field(role = other, encoding = ascii)]
    pub data: String,
}

pub fn openbsd_softraid_modes(value: &OpenbsdSoftraid) -> Vec<crate::Mode> {
    if value.iterations == 16 {
        vec![crate::Mode::Hashcat(38810)]
    } else {
        vec![crate::Mode::Hashcat(38800)]
    }
}

impl Parse for OpenbsdSoftraid {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$openbsd-softraid$", 0)?;
        let (iterations, data, data_offset) = parse::split_once(rest, '$', 19)?;
        if data.is_empty() {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                data_offset,
                "missing OpenBSD softraid data",
            ));
        }
        Ok(Self {
            iterations: iterations.parse::<u32>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    19,
                    "invalid OpenBSD softraid iteration count",
                )
            })?,
            data: data.to_owned(),
        })
    }
}

impl Render for OpenbsdSoftraid {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("$openbsd-softraid${}${}", self.iterations, self.data)
    }
}
