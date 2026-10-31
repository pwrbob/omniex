//! Kerberos 5 etype 18 DB hashes (John), rendered as `<realm>$<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Kerberos 5 etype 18 DB hashes in the John serialization.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "krb5-18 (John)", slug = "krb5-18", hashcat = [], john = ["krb5-18"])]
pub struct Krb5_18 {
    /// Kerberos principal.
    #[field(role = username, encoding = ascii)]
    pub principal: String,

    /// Hexadecimal digest.
    #[field(role = digest, encoding = ascii)]
    pub digest: String,
}

impl Parse for Krb5_18 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let (principal, digest, digest_offset) = parse::split_once(input, '$', 0)?;
        if digest.is_empty() {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                digest_offset,
                "missing Kerberos digest",
            ));
        }
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
