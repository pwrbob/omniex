//! Bouncy Castle BKS keystore extraction.

use std::str;

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::Bks;
use crate::{HashType, HashValue};

pub struct BksExtractor;

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], ExtractError> {
        let end = self
            .pos
            .checked_add(len)
            .filter(|end| *end <= self.data.len())
            .ok_or_else(|| ExtractError::Invalid("truncated BKS keystore".to_owned()))?;
        let value = &self.data[self.pos..end];
        self.pos = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, ExtractError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, ExtractError> {
        Ok(u16::from_be_bytes(
            self.take(2)?.try_into().expect("2 bytes"),
        ))
    }

    fn u32(&mut self) -> Result<u32, ExtractError> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().expect("4 bytes"),
        ))
    }

    fn utf(&mut self) -> Result<String, ExtractError> {
        let len = self.u16()? as usize;
        let value = self.take(len)?;
        str::from_utf8(value)
            .map(str::to_owned)
            .map_err(|_| ExtractError::Invalid("invalid BKS UTF-8 string".to_owned()))
    }

    fn data(&mut self) -> Result<&'a [u8], ExtractError> {
        let len = self.u32()? as usize;
        self.take(len)
    }
}

fn parse(artifact: &Artifact) -> Result<Bks, ExtractError> {
    let data = artifact.primary().read_all().map_err(|error| {
        ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
    })?;
    let mut reader = Reader::new(&data);
    let version = reader.u32()?;
    if !matches!(version, 1 | 2) {
        return Err(ExtractError::Unsupported(format!(
            "unsupported BKS keystore version {version}"
        )));
    }
    let salt_len = reader.u32()? as usize;
    if !(1..=1024).contains(&salt_len) {
        return Err(ExtractError::Invalid("invalid BKS salt length".to_owned()));
    }
    let salt = reader.take(salt_len)?;
    let iterations = reader.u32()?;

    let store_start = reader.pos;
    loop {
        let entry_type = reader.u8()?;
        if entry_type == 0 {
            break;
        }
        let _alias = reader.utf()?;
        reader.take(8)?;
        let chain_length = reader.u32()?;
        for _ in 0..chain_length {
            let _cert_type = reader.utf()?;
            let _cert = reader.data()?;
        }
        match entry_type {
            1 => {
                let _cert_type = reader.utf()?;
                let _cert = reader.data()?;
            }
            2 => {
                let _key_type = reader.u8()?;
                let _format = reader.utf()?;
                let _algorithm = reader.utf()?;
                let _key = reader.data()?;
            }
            3 | 4 => {
                let _entry = reader.data()?;
            }
            other => {
                return Err(ExtractError::Invalid(format!(
                    "unsupported BKS entry type {other}"
                )));
            }
        }
    }
    let store = &data[store_start..reader.pos];
    let hmac = reader.take(20)?;
    let hmac_key_size = if version == 1 { 20 } else { 160 };

    Ok(Bks {
        fields: format!(
            "0*{}*{}*{}*{}*{}*{}*{}",
            version,
            hmac_key_size,
            iterations,
            salt.len(),
            crate::format::hex(salt),
            crate::format::hex(store),
            crate::format::hex(hmac)
        ),
    })
}

impl Extractor for BksExtractor {
    fn slug(&self) -> &'static str {
        Bks::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match parse(artifact) {
            Ok(_) => Probe::yes("BKS keystore structure"),
            Err(_) => Probe::No,
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        Ok(vec![Box::new(parse(artifact)?) as Box<dyn HashValue>])
    }
}
