//! Kerberos 5, etype 23, AS-REQ pre-authentication hashes, rendered as
//! `$krb5pa$23$<user>$<realm>$<salt>$<timestamp>$<checksum>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Kerberos 5, etype 23, AS-REQ pre-authentication hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "Kerberos 5, etype 23, AS-REQ Pre-Auth",
    slug = "krb5pa23",
    hashcat = [7500],
    john = ["krb5pa-md5"]
)]
pub struct Krb5pa23 {
    /// Kerberos username
    #[field(role = username, encoding = ascii)]
    pub username: String,

    /// Kerberos realm
    #[field(role = other, encoding = ascii)]
    pub realm: String,

    /// Pre-authentication salt
    #[field(role = salt, encoding = ascii)]
    pub salt: String,

    /// 36-byte timestamp (hex)
    #[field(role = other, encoding = ascii)]
    pub timestamp: String,

    /// 16-byte checksum (hex)
    #[field(role = digest, encoding = ascii)]
    pub checksum: String,
}

impl Parse for Krb5pa23 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$krb5pa$23$", 0)?;
        let fields = parse::split_fields(rest, '$', 4)?;
        let tail = fields[3].0;
        if tail.len() != 104 {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                fields[3].1,
                "Kerberos timestamp and checksum must be 72 and 32 hex digits",
            ));
        }
        Ok(Self {
            username: fields[0].0.to_owned(),
            realm: fields[1].0.to_owned(),
            salt: fields[2].0.to_owned(),
            timestamp: tail[..72].to_owned(),
            checksum: tail[72..].to_owned(),
        })
    }
}

impl Render for Krb5pa23 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "$krb5pa$23${}${}${}${}{}",
            self.username, self.realm, self.salt, self.timestamp, self.checksum
        )
    }
}
