//! NTLMSSP exchange extraction for NetNTLMv1 and NetNTLMv2.
//!
//! Both hash types come from the same NTLMSSP challenge/authenticate pair, so
//! the message parser lives in [`ntlm`] and is shared by both extractors.

use std::collections::BTreeSet;

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::NetNtlmV1;
use crate::{HashType, HashValue};

pub(crate) mod ntlm {
    //! Minimal NTLMSSP message parser shared by the NetNTLM extractors.

    use super::super::{Artifact, ExtractError};
    use crate::extract::wpa_pmkid::net;

    const SIGNATURE: &[u8; 8] = b"NTLMSSP\0";
    const MAX_RAW_ARTIFACT: u64 = 64 * 1024 * 1024;
    const NEGOTIATE_UNICODE: u32 = 0x0000_0001;

    #[derive(Debug, Clone)]
    pub(crate) struct Authenticate {
        pub(crate) username: String,
        pub(crate) domain: String,
        pub(crate) lm_response: Vec<u8>,
        pub(crate) nt_response: Vec<u8>,
    }

    #[derive(Debug, Clone)]
    pub(crate) struct V1 {
        pub(crate) username: String,
        pub(crate) domain: String,
        pub(crate) lm_response: Vec<u8>,
        pub(crate) nt_response: [u8; 24],
        pub(crate) challenge: [u8; 8],
    }

    #[derive(Debug, Clone)]
    pub(crate) struct V2 {
        pub(crate) username: String,
        pub(crate) domain: String,
        pub(crate) challenge: [u8; 8],
        pub(crate) nt_proof: [u8; 16],
        pub(crate) blob: Vec<u8>,
    }

    #[derive(Debug, Clone)]
    pub(crate) enum Exchange {
        V1(V1),
        V2(V2),
    }

    enum Message {
        Challenge([u8; 8]),
        Authenticate(Authenticate),
    }

    fn truncated() -> ExtractError {
        ExtractError::Invalid("truncated NTLMSSP exchange".to_owned())
    }

    fn u16_at(data: &[u8], offset: usize) -> Option<usize> {
        let value = data.get(offset..offset + 2)?;
        Some(usize::from(u16::from_le_bytes([value[0], value[1]])))
    }

    fn u32_at(data: &[u8], offset: usize) -> Option<u32> {
        let value = data.get(offset..offset + 4)?;
        Some(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
    }

    fn buffer(data: &[u8], offset: usize) -> Option<Vec<u8>> {
        let length = u16_at(data, offset)?;
        let start = usize::try_from(u32_at(data, offset + 4)?).ok()?;
        let end = start.checked_add(length)?;
        Some(data.get(start..end)?.to_vec())
    }

    fn decode(value: &[u8], unicode: bool) -> String {
        if unicode {
            let units: Vec<u16> = value
                .chunks_exact(2)
                .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                .collect();
            String::from_utf16_lossy(&units)
        } else {
            String::from_utf8_lossy(value).into_owned()
        }
    }

    fn parse(data: &[u8]) -> Result<Option<Message>, ExtractError> {
        if data.len() < 12 {
            return Err(truncated());
        }
        match u32_at(data, 8) {
            Some(1) => Ok(None),
            Some(2) => {
                let challenge = data
                    .get(24..32)
                    .ok_or_else(truncated)?
                    .try_into()
                    .map_err(|_| truncated())?;
                if data.len() >= 48 {
                    let _ = buffer(data, 12);
                    let _ = buffer(data, 28);
                }
                Ok(Some(Message::Challenge(challenge)))
            }
            Some(3) => {
                if data.len() < 64 {
                    return Err(truncated());
                }
                let flags = u32_at(data, 60).ok_or_else(truncated)?;
                let unicode = flags & NEGOTIATE_UNICODE != 0;
                let lm_response = buffer(data, 12).ok_or_else(truncated)?;
                let nt_response = buffer(data, 20).ok_or_else(truncated)?;
                let domain = buffer(data, 28).ok_or_else(truncated)?;
                let username = buffer(data, 36).ok_or_else(truncated)?;
                if nt_response.is_empty() {
                    return Err(ExtractError::Invalid(
                        "NTLMSSP authenticate has no NT response".to_owned(),
                    ));
                }
                Ok(Some(Message::Authenticate(Authenticate {
                    username: decode(&username, unicode),
                    domain: decode(&domain, unicode),
                    lm_response,
                    nt_response,
                })))
            }
            Some(_) => Ok(None),
            None => Err(truncated()),
        }
    }

    fn scan_frame(frame: &[u8], messages: &mut Vec<Message>) -> Result<(), ExtractError> {
        let mut offset = 0;
        while let Some(found) = frame[offset..]
            .windows(SIGNATURE.len())
            .position(|window| window == SIGNATURE)
        {
            let start = offset + found;
            if let Some(message) = parse(&frame[start..])? {
                messages.push(message);
            }
            offset = start + SIGNATURE.len();
        }
        Ok(())
    }

    fn collect(artifact: &Artifact) -> Result<Vec<Message>, ExtractError> {
        let source = artifact.primary();
        let mut messages = Vec::new();
        if net::is_capture(source) {
            let mut failure = None;
            net::scan(source, |_, packet| {
                if failure.is_some() {
                    return;
                }
                if let Err(error) = scan_frame(packet, &mut messages) {
                    failure = Some(error);
                }
            })?;
            if let Some(error) = failure {
                return Err(error);
            }
        } else {
            if source.len() > MAX_RAW_ARTIFACT {
                return Err(ExtractError::Unsupported(
                    "NTLMSSP artifact is too large".to_owned(),
                ));
            }
            let data = source.read_all().map_err(|error| {
                ExtractError::Invalid(format!("cannot read NTLMSSP artifact: {error}"))
            })?;
            if data.len() < SIGNATURE.len() || &data[..SIGNATURE.len()] != SIGNATURE {
                return Err(ExtractError::Unsupported(
                    "not an NTLMSSP artifact".to_owned(),
                ));
            }
            scan_frame(&data, &mut messages)?;
        }
        Ok(messages)
    }

    /// Decodes every complete NTLMSSP challenge/authenticate exchange.
    pub(crate) fn exchanges(artifact: &Artifact) -> Result<Vec<Exchange>, ExtractError> {
        let mut result = Vec::new();
        let mut challenge = None;
        for message in collect(artifact)? {
            match message {
                Message::Challenge(value) => challenge = Some(value),
                Message::Authenticate(auth) => {
                    let Some(server) = challenge else {
                        return Err(ExtractError::Invalid(
                            "NTLMSSP authenticate without a server challenge".to_owned(),
                        ));
                    };
                    match auth.nt_response.len() {
                        24 => {
                            let nt_response = auth
                                .nt_response
                                .as_slice()
                                .try_into()
                                .map_err(|_| truncated())?;
                            let lm_response = if auth.lm_response.len() == 24 {
                                auth.lm_response
                            } else if auth.lm_response.is_empty() {
                                Vec::new()
                            } else {
                                return Err(ExtractError::Invalid(
                                    "NTLMSSP LM response has an unexpected length".to_owned(),
                                ));
                            };
                            result.push(Exchange::V1(V1 {
                                username: auth.username,
                                domain: auth.domain,
                                lm_response,
                                nt_response,
                                challenge: server,
                            }));
                        }
                        length if length > 24 => {
                            if length < 16 + 28 {
                                return Err(ExtractError::Invalid(
                                    "NTLMSSP NTLMv2 response is too short".to_owned(),
                                ));
                            }
                            let proof = auth
                                .nt_response
                                .get(..16)
                                .and_then(|value| value.try_into().ok())
                                .ok_or_else(truncated)?;
                            result.push(Exchange::V2(V2 {
                                username: auth.username,
                                domain: auth.domain,
                                challenge: server,
                                nt_proof: proof,
                                blob: auth.nt_response[16..].to_vec(),
                            }));
                        }
                        _ => {
                            return Err(ExtractError::Invalid(
                                "NTLMSSP NT response has an unexpected length".to_owned(),
                            ));
                        }
                    }
                }
            }
        }
        Ok(result)
    }
}

pub struct NetNtlmV1Extractor;

fn values(artifact: &Artifact) -> Result<Vec<NetNtlmV1>, ExtractError> {
    let mut records = BTreeSet::new();
    for exchange in ntlm::exchanges(artifact)? {
        if let ntlm::Exchange::V1(value) = exchange {
            records.insert((
                value.username,
                value.domain,
                value.lm_response,
                value.nt_response,
                value.challenge,
            ));
        }
    }
    Ok(records
        .into_iter()
        .map(
            |(username, domain, lm_response, nt_response, challenge)| NetNtlmV1 {
                username,
                domain,
                lm_response,
                nt_response,
                challenge,
            },
        )
        .collect())
}

impl Extractor for NetNtlmV1Extractor {
    fn slug(&self) -> &'static str {
        NetNtlmV1::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        match ntlm::exchanges(artifact) {
            Ok(exchanges)
                if exchanges
                    .iter()
                    .any(|value| matches!(value, ntlm::Exchange::V1(_))) =>
            {
                Probe::yes("NTLMSSP NetNTLMv1 challenge-response")
            }
            Ok(_) => Probe::No,
            Err(ExtractError::Unsupported(_)) => Probe::No,
            Err(ExtractError::Invalid(reason)) => Probe::maybe(reason),
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        let values = values(artifact)?;
        if values.is_empty() {
            return Err(ExtractError::Unsupported(
                "no NTLMSSP NetNTLMv1 exchanges".to_owned(),
            ));
        }
        Ok(values
            .into_iter()
            .map(|value| Box::new(value) as Box<dyn HashValue>)
            .collect())
    }
}
