//! BIP39 passphrase recovery hashes, rendered as
//! `<mnemonic>:<address>:<derivation path>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseOptions, Render, RenderOptions};

/// BIP39 passphrase recovery hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "BIP39 Passphrase Recovery",
    slug = "bip39",
    hashcat = [36000]
)]
pub struct Bip39 {
    /// Space-separated mnemonic words.
    #[field(role = salt, encoding = ascii)]
    pub mnemonic: String,

    /// Target Bitcoin address.
    #[field(role = other, encoding = ascii)]
    pub address: String,

    /// Derivation path.
    #[field(role = other, encoding = ascii)]
    pub path: String,
}

impl Parse for Bip39 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let fields = parse::split_fields(input, ':', 3)?;
        Ok(Self {
            mnemonic: fields[0].0.to_owned(),
            address: fields[1].0.to_owned(),
            path: fields[2].0.to_owned(),
        })
    }
}

impl Render for Bip39 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!("{}:{}:{}", self.mnemonic, self.address, self.path)
    }
}
