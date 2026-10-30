//! UUID v3 (RFC 4122 name-based, MD5), rendered as `<uuid>:<namespace>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// UUID v3 (RFC 4122 name-based, MD5) values.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "UUID v3 (RFC 4122 name-based, MD5)",
    slug = "uuid-v3",
    hashcat = [40004],
)]
pub struct UuidV3 {
    /// Generated UUID text.
    #[field(role = digest, encoding = ascii)]
    pub uuid: String,

    /// Namespace UUID text.
    #[field(role = other, encoding = ascii)]
    pub namespace: String,
}

impl Parse for UuidV3 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let (uuid, namespace, namespace_offset) = parse::split_once(input, ':', 0)?;
        if namespace.contains(':') {
            return Err(parse::error(
                ParseErrorKind::InvalidCharacter,
                namespace_offset,
                "namespace must not contain `:`",
            ));
        }
        Ok(Self {
            uuid: uuid.to_owned(),
            namespace: namespace.to_owned(),
        })
    }
}

impl Render for UuidV3 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("{}:{}", self.uuid, self.namespace)
    }
}
