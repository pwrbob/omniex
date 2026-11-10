//! Java KeyStore container password extraction.

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::Keystore;
use crate::{HashType, HashValue};

const JKS_MAX_BYTES: u64 = 16 * 1024 * 1024;
const JKS_MAGIC: u32 = 0xfeed_feed;
const JCEKS_MAGIC: u32 = 0xcece_cece;

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], ExtractError> {
        let end = self
            .pos
            .checked_add(length)
            .filter(|end| *end <= self.data.len())
            .ok_or_else(|| ExtractError::Invalid("truncated keystore field".to_owned()))?;
        let bytes = &self.data[self.pos..end];
        self.pos = end;
        Ok(bytes)
    }

    fn u32(&mut self) -> Result<u32, ExtractError> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes(
            bytes.try_into().expect("fixed keystore integer width"),
        ))
    }

    fn utf(&mut self) -> Result<(), ExtractError> {
        let length = {
            let bytes = self.take(2)?;
            usize::from(u16::from_be_bytes(
                bytes.try_into().expect("fixed keystore string width"),
            ))
        };
        self.take(length)?;
        Ok(())
    }

    fn field(&mut self) -> Result<&'a [u8], ExtractError> {
        let length = usize::try_from(self.u32()?)
            .map_err(|_| ExtractError::Invalid("keystore field is too long".to_owned()))?;
        self.take(length)
    }
}

fn parse(artifact: &Artifact) -> Result<Keystore, ExtractError> {
    if artifact.primary().len() > JKS_MAX_BYTES {
        return Err(ExtractError::Unsupported(format!(
            "{} is larger than the keystore limit",
            artifact.label()
        )));
    }
    let data = artifact.primary().read_all().map_err(|error| {
        ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
    })?;
    if data.len() < 12 {
        return Err(ExtractError::Unsupported("not a JKS keystore".to_owned()));
    }

    let mut reader = Reader::new(&data);
    let magic = reader.u32()?;
    if magic == JCEKS_MAGIC {
        return Err(ExtractError::Unsupported(
            "JCEKS keystore container MAC is not modeled".to_owned(),
        ));
    }
    if magic != JKS_MAGIC {
        return Err(ExtractError::Unsupported("not a JKS keystore".to_owned()));
    }
    let version = reader.u32()?;
    if version != 1 && version != 2 {
        return Err(ExtractError::Unsupported(format!(
            "unsupported JKS version {version}"
        )));
    }

    let count = reader.u32()?;
    let mut first_key = None;
    for _ in 0..count {
        match reader.u32()? {
            1 => {
                reader.utf()?;
                reader.take(8)?;
                let protected_key = reader.field()?;
                if first_key.is_none() {
                    first_key = Some(protected_key);
                }
                let certificates = reader.u32()?;
                for _ in 0..certificates {
                    if version == 2 {
                        reader.utf()?;
                    }
                    reader.field()?;
                }
            }
            2 => {
                reader.utf()?;
                reader.take(8)?;
                if version == 2 {
                    reader.utf()?;
                }
                reader.field()?;
            }
            tag => {
                return Err(ExtractError::Invalid(format!(
                    "unrecognized keystore entry tag {tag}"
                )));
            }
        }
    }

    let body_length = reader.pos;
    let mac = reader.take(20)?;
    if reader.pos != data.len() {
        return Err(ExtractError::Invalid(
            "trailing bytes after the keystore MAC".to_owned(),
        ));
    }

    let (key_count, key_length, key_data) = match first_key {
        Some(key) => (1, key.len(), crate::format::hex(key)),
        None => (0, 0, String::new()),
    };
    Ok(Keystore {
        fields: format!(
            "0${body_length}${}${}${key_count}${key_length}${key_data}",
            crate::format::hex(&data[..body_length]),
            crate::format::hex(mac)
        ),
    })
}

fn has_jceks_magic(artifact: &Artifact) -> bool {
    let mut magic = [0; 4];
    artifact.primary().read_exact_at(0, &mut magic).is_ok()
        && u32::from_be_bytes(magic) == JCEKS_MAGIC
}

pub struct KeystoreExtractor;

impl Extractor for KeystoreExtractor {
    fn slug(&self) -> &'static str {
        Keystore::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        if has_jceks_magic(artifact) {
            return Probe::maybe("JCEKS keystore container MAC is not modeled");
        }
        match parse(artifact) {
            Ok(_) => Probe::yes("JKS keystore container structure"),
            Err(_) => Probe::No,
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        Ok(vec![Box::new(parse(artifact)?) as Box<dyn HashValue>])
    }
}
