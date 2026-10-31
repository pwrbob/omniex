//! Kerberos 4 hashes, rendered as `$af$<realm>$<data>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Kerberos 4 hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "Kerberos 4", slug = "krb4", hashcat = [], john = ["krb4"])]
pub struct Krb4 {
    /// Realm.
    #[field(role = other, encoding = ascii)]
    pub realm: String,

    /// Encrypted data.
    #[field(role = ciphertext, encoding = ascii)]
    pub data: String,
}

impl Parse for Krb4 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$af$", 0)?;
        let (realm, data, data_offset) = parse::split_once(rest, '$', 4)?;
        if data.is_empty() {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                data_offset,
                "missing Kerberos 4 data",
            ));
        }
        Ok(Self {
            realm: realm.to_owned(),
            data: data.to_owned(),
        })
    }
}

impl Render for Krb4 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("$af${}${}", self.realm, self.data)
    }
}
