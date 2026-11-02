//! Plain hash lists, one hash per line or in `user:hash` form.

use std::str;

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::{
    Blake2b256, Blake2b512, Blake2s256, EdonR256, EdonR512, Fugue, Gost, Groestl, Hamsi, Has160,
    Jh, Keccak, Lm, Luffa, Md2, Md4, Md5, Md6, Mdc2, Panama, RadioGatun, Ripemd, Sha0, Sha1, Sha3,
    Sha224, Sha256, Sha384, Sha512, Shabal, Shavite3, Simd, Skein512, Sm3, Snefru, Streebog, Tiger,
    Whirlpool,
};
use crate::{HashType, HashValue, Parse, ParseOptions};

pub(crate) fn candidates(data: &[u8]) -> Result<Vec<String>, ExtractError> {
    let text = str::from_utf8(data)
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

pub(crate) fn extract_from_data<T>(data: &[u8]) -> Result<Vec<T>, ExtractError>
where
    T: Parse + HashValue + 'static,
{
    let opts = ParseOptions::default();
    let mut hashes = Vec::new();
    for value in candidates(data)? {
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

pub(crate) fn probe_data<T>(data: &[u8]) -> Probe
where
    T: Parse + HashValue + 'static,
{
    match extract_from_data::<T>(data) {
        Ok(_) => Probe::maybe("hash list entry"),
        Err(_) => Probe::No,
    }
}

fn read_data(artifact: &Artifact) -> Result<Vec<u8>, ExtractError> {
    artifact.primary().read_all().map_err(|error| {
        ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
    })
}

fn extract<T>(artifact: &Artifact) -> Result<Vec<T>, ExtractError>
where
    T: Parse + HashValue + 'static,
{
    extract_from_data::<T>(&read_data(artifact)?)
}

fn probe<T>(artifact: &Artifact) -> Probe
where
    T: Parse + HashValue + 'static,
{
    match read_data(artifact) {
        Ok(data) => probe_data::<T>(&data),
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
list_extractor!(Blake2b256Extractor, Blake2b256);
list_extractor!(Blake2b512Extractor, Blake2b512);
list_extractor!(Blake2s256Extractor, Blake2s256);
list_extractor!(EdonR256Extractor, EdonR256);
list_extractor!(Has160Extractor, Has160);
list_extractor!(Mdc2Extractor, Mdc2);
list_extractor!(Md6Extractor, Md6);
list_extractor!(PanamaExtractor, Panama);
list_extractor!(RadioGatunExtractor, RadioGatun);
list_extractor!(SnefruExtractor, Snefru);
list_extractor!(EdonR512Extractor, EdonR512);
list_extractor!(FugueExtractor, Fugue);
list_extractor!(GroestlExtractor, Groestl);
list_extractor!(HamsiExtractor, Hamsi);
list_extractor!(JhExtractor, Jh);
list_extractor!(LuffaExtractor, Luffa);
list_extractor!(ShabalExtractor, Shabal);
list_extractor!(Shavite3Extractor, Shavite3);
list_extractor!(SimdExtractor, Simd);
