//! Bitcoin Core wallet hashes, rendered as
//! `$bitcoin$<master length>$<master>$<salt length>$<salt>$<rounds>$<ckey length>$<ckey>$<public key length>$<public key>`.

use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

/// Bitcoin Core `wallet.dat` hashes.
#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "Bitcoin/Litecoin wallet.dat", slug = "bitcoin-wallet", hashcat = [11300], john = ["Bitcoin"])]
pub struct BitcoinWallet {
    /// Encrypted master key.
    #[field(role = ciphertext, encoding = hex)]
    pub master: Vec<u8>,

    /// Initialization vector.
    #[field(role = salt, encoding = hex)]
    pub salt: Vec<u8>,

    /// Key derivation round count.
    #[field(role = other, encoding = decimal)]
    pub rounds: u64,

    /// Encrypted private key, empty when unavailable.
    #[field(role = ciphertext, encoding = hex)]
    pub ckey: Vec<u8>,

    /// Public key, empty when unavailable.
    #[field(role = other, encoding = hex)]
    pub public_key: Vec<u8>,
}

impl Parse for BitcoinWallet {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "$bitcoin$", 0)?;
        let fields = parse::split_fields(rest, '$', 9)?;
        let parse_length = |field: &str, base: usize, name: &str| -> Result<usize, ParseError> {
            field.parse::<usize>().map_err(|_| {
                parse::error(
                    ParseErrorKind::InvalidCharacter,
                    base,
                    format!("invalid Bitcoin {name} length"),
                )
            })
        };

        let master_len = parse_length(fields[0].0, 10, "master key")?;
        let salt_len = parse_length(fields[2].0, fields[2].1, "salt")?;
        let rounds = fields[4].0.parse::<u64>().map_err(|_| {
            parse::error(
                ParseErrorKind::InvalidCharacter,
                fields[4].1,
                "invalid Bitcoin round count",
            )
        })?;
        let ckey_len = parse_length(fields[5].0, fields[5].1, "private key")?;
        let public_key_len = parse_length(fields[7].0, fields[7].1, "public key")?;

        if fields[1].0.len() != master_len || master_len < 64 || master_len % 32 != 0 {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                fields[1].1,
                "Bitcoin master key length does not match its header",
            ));
        }
        if fields[3].0.len() != salt_len || !matches!(salt_len, 16 | 36) {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                fields[3].1,
                "Bitcoin salts are 8 or 18 bytes",
            ));
        }
        if fields[6].0.len() != ckey_len || fields[8].0.len() != public_key_len {
            return Err(parse::error(
                ParseErrorKind::InvalidLength,
                fields[6].1,
                "Bitcoin key length does not match its header",
            ));
        }

        Ok(Self {
            master: parse::decode_hex(fields[1].0, fields[1].1)?,
            salt: parse::decode_hex(fields[3].0, fields[3].1)?,
            rounds,
            ckey: parse::decode_hex(fields[6].0, fields[6].1)?,
            public_key: parse::decode_hex(fields[8].0, fields[8].1)?,
        })
    }
}

impl Render for BitcoinWallet {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        let master = crate::format::hex(&self.master);
        let salt = crate::format::hex(&self.salt);
        let ckey = crate::format::hex(&self.ckey);
        let public_key = crate::format::hex(&self.public_key);
        format!(
            "$bitcoin${}${}${}${}${}${}${}${}${}",
            master.len(),
            master,
            salt.len(),
            salt,
            self.rounds,
            ckey.len(),
            ckey,
            public_key.len(),
            public_key
        )
    }
}
