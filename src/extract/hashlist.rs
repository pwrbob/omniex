//! Plain hash lists, one hash per line or in `user:hash` form.

use std::str;

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::{
    Gost, Keccak, Lm, Md2, Md4, Md5, Ntlm, Ripemd, Sha0, Sha1, Sha3, Sha224, Sha256, Sha384,
    Sha512, Skein512, Sm3, Streebog, Tiger, Whirlpool,
};
use crate::{HashType, HashValue, Parse, ParseOptions};

fn candidates(artifact: &Artifact) -> Result<Vec<String>, ExtractError> {
    let data = artifact.primary().read_all().map_err(|error| {
        ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
    })?;
    let text = str::from_utf8(&data)
        .map_err(|_| ExtractError::Invalid("hash list is not UTF-8".to_owned()))?;
    let mut values = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let hash = line.rsplit_once(':').map_or(line, |(_, hash)| hash.trim());
        values.push(hash.to_owned());
    }
    Ok(values)
}

fn extract<T>(artifact: &Artifact) -> Result<Vec<T>, ExtractError>
where
    T: Parse + HashValue + 'static,
{
    let opts = ParseOptions::default();
    let mut hashes = Vec::new();
    for value in candidates(artifact)? {
        if let Ok(hash) = T::parse(&value, &opts) {
            hashes.push(hash);
        }
    }
    if hashes.is_empty() {
        return Err(ExtractError::Unsupported(
            "no matching hashes found".to_owned(),
        ));
    }
    Ok(hashes)
}

fn probe<T>(artifact: &Artifact) -> Probe
where
    T: Parse + HashValue + 'static,
{
    match extract::<T>(artifact) {
        Ok(_) => Probe::maybe("hash list entry"),
        Err(_) => Probe::No,
    }
}

macro_rules! list_extractor {
    ($name:ident, $ty:ty) => {
        pub struct $name;
        impl Extractor for $name {
            fn slug(&self) -> &'static str {
                <$ty>::SLUG
            }

            fn exact(&self) -> bool {
                false
            }
            fn probe(&self, artifact: &Artifact) -> Probe {
                probe::<$ty>(artifact)
            }
            fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
                Ok(extract::<$ty>(artifact)?
                    .into_iter()
                    .map(|hash| Box::new(hash) as Box<dyn HashValue>)
                    .collect())
            }
        }
    };
}

list_extractor!(LmExtractor, Lm);
list_extractor!(Md4Extractor, Md4);
list_extractor!(Md5Extractor, Md5);
list_extractor!(NtlmExtractor, Ntlm);
list_extractor!(RipemdExtractor, Ripemd);
list_extractor!(Sha1Extractor, Sha1);
list_extractor!(Sha224Extractor, Sha224);
list_extractor!(Sha256Extractor, Sha256);
list_extractor!(Sha384Extractor, Sha384);
list_extractor!(Sha512Extractor, Sha512);
list_extractor!(GostExtractor, Gost);
list_extractor!(KeccakExtractor, Keccak);
list_extractor!(Md2Extractor, Md2);
list_extractor!(Sha0Extractor, Sha0);
list_extractor!(Sha3Extractor, Sha3);
list_extractor!(Sm3Extractor, Sm3);
list_extractor!(Skein512Extractor, Skein512);
list_extractor!(StreebogExtractor, Streebog);
list_extractor!(TigerExtractor, Tiger);
list_extractor!(WhirlpoolExtractor, Whirlpool);
