//! Bitcoin WIF private keys, rendered as the derived address.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Bitcoin WIF private key targets.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(
    name = "Bitcoin WIF private key",
    slug = "bitcoin-wif",
    hashcat = [
        28501, 28502, 28503, 28504, 28505, 28506, 30901, 30902, 30903, 30904, 30905, 30906,
    ],
    modes_fn = bitcoin_wif_modes,
)]
pub struct BitcoinWif {
    /// Bitcoin address text.
    #[field(role = other, encoding = ascii)]
    pub address: String,
}

pub fn bitcoin_wif_modes(value: &BitcoinWif) -> Vec<crate::Mode> {
    let valid = value.address.starts_with('1')
        || value.address.starts_with('3')
        || value.address.starts_with("bc1");
    if valid {
        BitcoinWif::DESCRIPTOR.all_modes.to_vec()
    } else {
        Vec::new()
    }
}

impl Parse for BitcoinWif {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        if !(input.starts_with('1') || input.starts_with('3') || input.starts_with("bc1")) {
            return Err(parse::error(
                ParseErrorKind::InvalidCharacter,
                0,
                "expected a Base58Check or Bech32 Bitcoin address",
            ));
        }
        Ok(Self {
            address: input.to_owned(),
        })
    }
}

impl Render for BitcoinWif {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        self.address.clone()
    }
}
