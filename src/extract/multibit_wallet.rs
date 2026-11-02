//! MultiBit Classic `.wallet` (bitcoinj protobuf) extraction.

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::MultibitWallet;
use crate::{HashType, HashValue};

pub struct MultibitWalletExtractor;

#[derive(Debug, Clone, Copy)]
enum Field<'a> {
    Varint(u64),
    Bytes(&'a [u8]),
    Fixed32,
    Fixed64,
}

struct Reader<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }

    fn varint(&mut self) -> Result<u64, ExtractError> {
        let mut value = 0u64;
        for shift in (0..64).step_by(7) {
            let byte = *self
                .data
                .get(self.offset)
                .ok_or_else(|| ExtractError::Invalid("truncated MultiBit protobuf".to_owned()))?;
            self.offset += 1;
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err(ExtractError::Invalid(
            "MultiBit protobuf varint is too long".to_owned(),
        ))
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], ExtractError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or_else(|| ExtractError::Invalid("MultiBit protobuf length overflow".to_owned()))?;
        let bytes = self
            .data
            .get(self.offset..end)
            .ok_or_else(|| ExtractError::Invalid("truncated MultiBit protobuf".to_owned()))?;
        self.offset = end;
        Ok(bytes)
    }

    fn next(&mut self) -> Result<Option<(u64, Field<'a>)>, ExtractError> {
        if self.offset == self.data.len() {
            return Ok(None);
        }
        let key = self.varint()?;
        let field = key >> 3;
        let wire = key & 7;
        let value = match wire {
            0 => Field::Varint(self.varint()?),
            1 => {
                self.take(8)?;
                Field::Fixed64
            }
            2 => {
                let length = usize::try_from(self.varint()?).map_err(|_| {
                    ExtractError::Invalid("MultiBit protobuf field is too large".to_owned())
                })?;
                Field::Bytes(self.take(length)?)
            }
            5 => {
                self.take(4)?;
                Field::Fixed32
            }
            _ => {
                return Err(ExtractError::Invalid(
                    "unsupported MultiBit protobuf wire type".to_owned(),
                ));
            }
        };
        Ok(Some((field, value)))
    }
}

#[derive(Default)]
struct ScryptParameters {
    salt: Option<[u8; 8]>,
    n: Option<u64>,
    r: Option<u64>,
    p: Option<u64>,
}

fn parse_scrypt(data: &[u8]) -> Result<ScryptParameters, ExtractError> {
    let mut parameters = ScryptParameters::default();
    let mut reader = Reader::new(data);
    while let Some((field, value)) = reader.next()? {
        match (field, value) {
            (1, Field::Bytes(salt)) if salt.len() == 8 => {
                parameters.salt = Some(salt.try_into().expect("8-byte salt"));
            }
            (2, Field::Varint(n)) => parameters.n = Some(n),
            (3, Field::Varint(r)) => parameters.r = Some(r),
            (4, Field::Varint(p)) => parameters.p = Some(p),
            _ => {}
        }
    }
    Ok(parameters)
}

fn parse_encrypted_data(data: &[u8]) -> Result<Option<Vec<u8>>, ExtractError> {
    let mut encrypted = None;
    let mut reader = Reader::new(data);
    while let Some((field, value)) = reader.next()? {
        if field == 2 {
            if let Field::Bytes(key) = value {
                encrypted = Some(key.to_vec());
            }
        }
    }
    Ok(encrypted)
}

struct Key {
    kind: u64,
    encrypted: Option<Vec<u8>>,
}

fn parse_key(data: &[u8]) -> Result<Key, ExtractError> {
    let mut kind = 0;
    let mut encrypted = None;
    let mut reader = Reader::new(data);
    while let Some((field, value)) = reader.next()? {
        match (field, value) {
            (1, Field::Varint(value)) => kind = value,
            (6, Field::Bytes(data)) => encrypted = parse_encrypted_data(data)?,
            _ => {}
        }
    }
    Ok(Key { kind, encrypted })
}

fn parse(artifact: &Artifact) -> Result<Vec<MultibitWallet>, ExtractError> {
    let data = artifact.primary().read_all().map_err(|error| {
        ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
    })?;
    if data.is_empty() {
        return Err(ExtractError::Invalid(
            "MultiBit wallet file is empty".to_owned(),
        ));
    }

    let mut encryption_type = None;
    let mut parameters = None;
    let mut keys = Vec::new();
    let mut reader = Reader::new(&data);
    while let Some((field, value)) = reader.next()? {
        match (field, value) {
            (3, Field::Bytes(data)) => keys.push(parse_key(data)?),
            (5, Field::Varint(value)) => encryption_type = Some(value),
            (6, Field::Bytes(data)) => parameters = Some(parse_scrypt(data)?),
            _ => {}
        }
    }

    if encryption_type != Some(2) {
        return Err(ExtractError::Unsupported(
            "MultiBit wallet is not encrypted with scrypt".to_owned(),
        ));
    }
    let parameters = parameters.ok_or_else(|| {
        ExtractError::Invalid("MultiBit wallet has no scrypt parameters".to_owned())
    })?;
    let salt = parameters
        .salt
        .ok_or_else(|| ExtractError::Invalid("MultiBit wallet has no scrypt salt".to_owned()))?;
    let n = parameters.n.unwrap_or(16384);
    let r = parameters.r.unwrap_or(8);
    let p = parameters.p.unwrap_or(1);
    if n < 2 || !n.is_power_of_two() {
        return Err(ExtractError::Invalid(
            "MultiBit scrypt cost is not a power of two".to_owned(),
        ));
    }
    if r == 0 || p == 0 {
        return Err(ExtractError::Invalid(
            "MultiBit scrypt parameters are zero".to_owned(),
        ));
    }
    let n = u32::try_from(n)
        .map_err(|_| ExtractError::Invalid("MultiBit scrypt cost is too large".to_owned()))?;
    let r = u32::try_from(r)
        .map_err(|_| ExtractError::Invalid("MultiBit scrypt block size is too large".to_owned()))?;
    let p = u32::try_from(p).map_err(|_| {
        ExtractError::Invalid("MultiBit scrypt parallelization is too large".to_owned())
    })?;

    let mut values = Vec::new();
    for key in keys {
        if !matches!(key.kind, 2 | 4) {
            continue;
        }
        let Some(encrypted) = key.encrypted else {
            continue;
        };
        if encrypted.len() != 48 {
            continue;
        }
        values.push(MultibitWallet {
            n,
            r,
            p,
            salt,
            digest: encrypted[16..48].try_into().expect("32-byte digest"),
        });
    }

    if values.is_empty() {
        return Err(ExtractError::Unsupported(
            "MultiBit wallet has no encrypted keys".to_owned(),
        ));
    }
    Ok(values)
}

impl Extractor for MultibitWalletExtractor {
    fn slug(&self) -> &'static str {
        MultibitWallet::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match parse(artifact) {
            Ok(values) if !values.is_empty() => Probe::yes("MultiBit Classic protobuf wallet"),
            _ => Probe::No,
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        Ok(parse(artifact)?
            .into_iter()
            .map(|value| Box::new(value) as Box<dyn HashValue>)
            .collect())
    }
}
