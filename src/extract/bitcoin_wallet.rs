//! Bitcoin Core `wallet.dat` Berkeley DB extraction.

use super::{Artifact, ExtractError, Extracted, Extractor, Probe, ReadAt};
use crate::types::BitcoinWallet;
use crate::{HashType, HashValue};

pub struct BitcoinWalletExtractor;

const PAGE_HEADER: usize = 26;
const P_LBTREE: u8 = 5;
const B_KEYDATA: u8 = 1;
const B_OVERFLOW: u8 = 3;

fn u16_at(data: &[u8], offset: usize) -> Option<u16> {
    let bytes = data.get(offset..offset + 2)?;
    Some(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn u32_at(data: &[u8], offset: usize) -> Option<u32> {
    let bytes = data.get(offset..offset + 4)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn compact_size(data: &[u8], offset: &mut usize) -> Result<u64, ExtractError> {
    let first = *data
        .get(*offset)
        .ok_or_else(|| ExtractError::Invalid("truncated Bitcoin wallet record".to_owned()))?;
    *offset += 1;
    let (value, width) = match first {
        0..=252 => (u64::from(first), 0),
        253 => (0, 2),
        254 => (0, 4),
        255 => (0, 8),
    };
    if width == 0 {
        return Ok(value);
    }
    let bytes = data
        .get(*offset..*offset + width)
        .ok_or_else(|| ExtractError::Invalid("truncated Bitcoin wallet record".to_owned()))?;
    *offset += width;
    let value = match width {
        2 => u64::from(u16::from_le_bytes([bytes[0], bytes[1]])),
        4 => u64::from(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])),
        8 => u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]),
        _ => unreachable!(),
    };
    Ok(value)
}

fn compact_bytes<'a>(data: &'a [u8], offset: &mut usize) -> Result<&'a [u8], ExtractError> {
    let length = usize::try_from(compact_size(data, offset)?)
        .map_err(|_| ExtractError::Invalid("Bitcoin wallet record is too large".to_owned()))?;
    let end = (*offset)
        .checked_add(length)
        .ok_or_else(|| ExtractError::Invalid("Bitcoin wallet record overflow".to_owned()))?;
    let bytes = data
        .get(*offset..end)
        .ok_or_else(|| ExtractError::Invalid("truncated Bitcoin wallet record".to_owned()))?;
    *offset = end;
    Ok(bytes)
}

fn item(page: &[u8], index: usize) -> Option<Result<Vec<u8>, ExtractError>> {
    let offset = usize::from(u16_at(page, PAGE_HEADER + index * 2)?);
    let entry = page.get(offset..)?;
    let kind = *entry.get(2)?;
    match kind & 0x7f {
        B_KEYDATA => {
            let length = usize::from(u16_at(entry, 0)?);
            Some(
                entry.get(3..3 + length).map(<[u8]>::to_vec).ok_or_else(|| {
                    ExtractError::Invalid("truncated Bitcoin wallet item".to_owned())
                }),
            )
        }
        B_OVERFLOW => Some(Err(ExtractError::Unsupported(
            "Bitcoin wallet record is stored on an overflow page".to_owned(),
        ))),
        _ => None,
    }
}

fn parse_record(value: &[u8]) -> Result<BitcoinWallet, ExtractError> {
    let mut offset = 0;
    let master = compact_bytes(value, &mut offset)?.to_vec();
    let salt = compact_bytes(value, &mut offset)?.to_vec();
    let method = u32_at(value, offset)
        .ok_or_else(|| ExtractError::Invalid("truncated Bitcoin derivation method".to_owned()))?;
    offset += 4;
    let rounds = u32_at(value, offset)
        .ok_or_else(|| ExtractError::Invalid("truncated Bitcoin round count".to_owned()))?;
    if method != 0 {
        return Err(ExtractError::Unsupported(
            "Bitcoin wallet uses an unknown key derivation method".to_owned(),
        ));
    }
    let expected = match salt.len() {
        8 => 48,
        18 => 80,
        _ => {
            return Err(ExtractError::Unsupported(
                "Bitcoin wallet uses an unsupported salt size".to_owned(),
            ));
        }
    };
    if master.len() != expected {
        return Err(ExtractError::Unsupported(
            "Bitcoin wallet uses an unsupported master key size".to_owned(),
        ));
    }
    Ok(BitcoinWallet {
        master,
        salt,
        rounds: u64::from(rounds),
        ckey: Vec::new(),
        public_key: Vec::new(),
    })
}

fn page_size(source: &dyn ReadAt) -> Result<usize, ExtractError> {
    let mut header = [0; PAGE_HEADER];
    source
        .read_exact_at(0, &mut header)
        .map_err(|_| ExtractError::Invalid("Bitcoin wallet is too short".to_owned()))?;
    let size = usize::try_from(
        u32_at(&header, 20)
            .ok_or_else(|| ExtractError::Invalid("Bitcoin wallet has no page size".to_owned()))?,
    )
    .map_err(|_| ExtractError::Invalid("Bitcoin wallet page size is invalid".to_owned()))?;
    if !(512..=65536).contains(&size) || !size.is_power_of_two() {
        return Err(ExtractError::Invalid(
            "Bitcoin wallet page size is invalid".to_owned(),
        ));
    }
    Ok(size)
}

fn parse(artifact: &Artifact) -> Result<Vec<BitcoinWallet>, ExtractError> {
    let source = artifact.primary();
    if source.is_empty() {
        return Err(ExtractError::Invalid("Bitcoin wallet is empty".to_owned()));
    }
    let page_size = page_size(source)?;
    let pages = source.len() / page_size as u64;
    let mut values = Vec::new();
    let mut page = 1;
    while page < pages {
        let mut data = vec![0; page_size];
        let offset = page * page_size as u64;
        let read = source.read_at(offset, &mut data).map_err(|error| {
            ExtractError::Invalid(format!("cannot read Bitcoin wallet: {error}"))
        })?;
        data.truncate(read);
        page += 1;
        if data.len() < PAGE_HEADER || data[25] != P_LBTREE {
            continue;
        }
        let entries = usize::from(u16_at(&data, 20).unwrap_or(0));
        if entries == 0 || entries % 2 != 0 || entries > (page_size - PAGE_HEADER) / 2 {
            continue;
        }
        for pair in 0..entries / 2 {
            let Some(key) = item(&data, pair * 2) else {
                continue;
            };
            let key = match key {
                Ok(key) => key,
                Err(_) => continue,
            };
            let mut key_offset = 0;
            let Ok(name) = compact_bytes(&key, &mut key_offset) else {
                continue;
            };
            if name != b"mkey" {
                continue;
            }
            let Some(value) = item(&data, pair * 2 + 1) else {
                continue;
            };
            let value = value?;
            values.push(parse_record(&value)?);
        }
    }
    if values.is_empty() {
        return Err(ExtractError::Unsupported(
            "Bitcoin wallet has no encrypted master key".to_owned(),
        ));
    }
    Ok(values)
}

impl Extractor for BitcoinWalletExtractor {
    fn slug(&self) -> &'static str {
        BitcoinWallet::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match parse(artifact) {
            Ok(values) if !values.is_empty() => Probe::yes("Bitcoin Core wallet.dat mkey record"),
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
