//! Kerberos 5 etype 18 DB hashes, rendered as `<realm>$<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Kerberos 5 etype 18 DB hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "Kerberos 5 etype 18", slug = "krb5-18", hashcat = [], john = ["krb5-18"])]
pub struct Krb5_18 {
    /// Kerberos principal.
    #[field(role = username, encoding = ascii)]
    pub principal: String,

    /// Hexadecimal digest.
    #[field(role = digest, encoding = ascii)]
    pub digest: String,
}

const TAG: &str = "$krb18$";

impl Parse for Krb5_18 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let base = usize::from(input.starts_with(TAG)) * TAG.len();
        let rest = input.get(base..).unwrap_or_default();
        let (principal, digest, digest_offset) = parse::split_once(rest, '$', base)?;
        if principal.is_empty() {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                base,
                "missing Kerberos principal",
            ));
        }
        parse::check_text_length(principal, base, 128, "Kerberos principal")?;
        if digest.len() != 64 {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                digest_offset,
                "Kerberos etype 18 digests are 64 hexadecimal digits",
            ));
        }
        parse::check_hex(digest, digest_offset, "Kerberos digest")?;
        Ok(Self {
            principal: principal.to_owned(),
            digest: digest.to_owned(),
        })
    }
}

impl Render for Krb5_18 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("{}${}", self.principal, self.digest)
    }
}
