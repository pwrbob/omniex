//! Legacy Kerberos 5 DB hashes, rendered as `$krb5db$<etype>$<user>$<realm>$<digest>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Legacy Kerberos 5 database hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "Kerberos 5, etype 1/2/3, DB",
    slug = "krb5db-old",
    hashcat = [38400],
)]
pub struct Krb5DbOld {
    /// Kerberos encryption type.
    #[field(role = other, encoding = decimal)]
    pub etype: u8,

    /// Kerberos username.
    #[field(role = username, encoding = ascii)]
    pub username: String,

    /// Kerberos realm.
    #[field(role = other, encoding = ascii)]
    pub realm: String,

    /// The 8-byte key digest.
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 8],
}

impl Parse for Krb5DbOld {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$krb5db$", 0)?;
        let fields = parse::split_fields(rest, '$', 4)?;
        let etype = fields[0].0.parse::<u8>().map_err(|_| {
            parse::error(
                ParseErrorKind::InvalidCharacter,
                8,
                "invalid Kerberos encryption type",
            )
        })?;
        if !(1..=3).contains(&etype) {
            return Err(parse::error(
                ParseErrorKind::InvalidCharacter,
                8,
                "legacy Kerberos DB encryption type must be 1, 2, or 3",
            ));
        }
        Ok(Self {
            etype,
            username: fields[1].0.to_owned(),
            realm: fields[2].0.to_owned(),
            digest: parse::decode_hex_field::<8>(fields[3].0, fields[3].1, "digest")?,
        })
    }
}

impl Render for Krb5DbOld {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$krb5db${}${}${}${}",
            self.etype,
            self.username,
            self.realm,
            crate::format::hex(self.digest)
        )
    }
}
