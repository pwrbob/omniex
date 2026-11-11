//! 7-Zip archive AES encryption extraction.

use lzma_rs::decompress::raw::{Lzma2Decoder, LzmaDecoder, LzmaParams, LzmaProperties};

use super::{Artifact, ExtractError, Extracted, Extractor, Probe};
use crate::types::SevenZip;
use crate::{HashType, HashValue};

pub struct SevenZipExtractor;

const SIGNATURE: &[u8] = b"7z\xbc\xaf\x27\x1c";

const END: u8 = 0x00;
const HEADER: u8 = 0x01;
const ARCHIVE_PROPERTIES: u8 = 0x02;
const ADD_STREAMS_INFO: u8 = 0x03;
const MAIN_STREAMS_INFO: u8 = 0x04;
const PACK_INFO: u8 = 0x06;
const UNPACK_INFO: u8 = 0x07;
const SUBSTREAMS_INFO: u8 = 0x08;
const SIZE: u8 = 0x09;
const CRC: u8 = 0x0a;
const FOLDER: u8 = 0x0b;
const UNPACK_SIZE: u8 = 0x0c;
const NUM_UNPACK_STREAM: u8 = 0x0d;
const ENCODED_HEADER: u8 = 0x17;

const AES: &[u8] = &[0x06, 0xf1, 0x07, 0x01];

struct Cursor<'a> {
    data: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, position: 0 }
    }

    fn byte(&mut self) -> Result<u8, ExtractError> {
        let byte = *self
            .data
            .get(self.position)
            .ok_or_else(|| ExtractError::Invalid("truncated 7-Zip header".to_owned()))?;
        self.position += 1;
        Ok(byte)
    }

    fn bytes(&mut self, len: usize) -> Result<&'a [u8], ExtractError> {
        let end = self
            .position
            .checked_add(len)
            .ok_or_else(|| ExtractError::Invalid("7-Zip length overflow".to_owned()))?;
        let bytes = self
            .data
            .get(self.position..end)
            .ok_or_else(|| ExtractError::Invalid("truncated 7-Zip header".to_owned()))?;
        self.position = end;
        Ok(bytes)
    }

    fn uint32(&mut self) -> Result<u32, ExtractError> {
        let bytes = self.bytes(4)?;
        Ok(u32::from_le_bytes(
            bytes.try_into().expect("four-byte slice"),
        ))
    }

    fn uint64(&mut self) -> Result<u64, ExtractError> {
        let bytes = self.bytes(8)?;
        Ok(u64::from_le_bytes(
            bytes.try_into().expect("eight-byte slice"),
        ))
    }

    fn number(&mut self) -> Result<u64, ExtractError> {
        let first = self.byte()?;
        if first & 0x80 == 0 {
            return Ok(u64::from(first));
        }
        let mut value = u64::from(self.byte()?);
        let mut mask = 0x80u8;
        for index in 1..8 {
            mask >>= 1;
            if first & mask == 0 {
                let high = u64::from(first & (mask - 1));
                value |= high << (index * 8);
                return Ok(value);
            }
            value |= u64::from(self.byte()?) << (index * 8);
        }
        Ok(value)
    }

    fn id(&mut self) -> Result<Vec<u8>, ExtractError> {
        let number = self.number()?;
        Ok(number_to_id(number))
    }

    fn skip_data(&mut self) -> Result<(), ExtractError> {
        let len = self.byte()? as usize;
        self.bytes(len).map(|_| ())
    }
}

fn number_to_id(number: u64) -> Vec<u8> {
    if number == 0 {
        return vec![0];
    }
    let mut id = Vec::new();
    let mut value = number;
    while value > 0 {
        id.push((value & 0xff) as u8);
        value >>= 8;
    }
    id.reverse();
    id
}

fn wait_for_id(cursor: &mut Cursor<'_>, wanted: u8) -> Result<bool, ExtractError> {
    loop {
        let id = cursor.id()?;
        if id == [wanted] {
            return Ok(true);
        }
        if id == [END] {
            return Ok(false);
        }
        cursor.skip_data()?;
    }
}

fn boolean_vector(cursor: &mut Cursor<'_>, count: usize) -> Result<Vec<bool>, ExtractError> {
    let mut values = Vec::with_capacity(count);
    let mut byte = 0u8;
    let mut mask = 0u8;
    for _ in 0..count {
        if mask == 0 {
            byte = cursor.byte()?;
            mask = 0x80;
        }
        values.push(byte & mask != 0);
        mask >>= 1;
    }
    Ok(values)
}

fn boolean_vector_check_all(
    cursor: &mut Cursor<'_>,
    count: usize,
) -> Result<Vec<bool>, ExtractError> {
    let all = cursor.byte()?;
    if all == 1 {
        Ok(vec![true; count])
    } else {
        boolean_vector(cursor, count)
    }
}

fn digests(cursor: &mut Cursor<'_>, count: usize) -> Result<Vec<Option<u32>>, ExtractError> {
    let defined = boolean_vector_check_all(cursor, count)?;
    let mut values = Vec::with_capacity(count);
    for is_defined in defined {
        let value = cursor.uint32()?;
        values.push(is_defined.then_some(value));
    }
    Ok(values)
}

struct Coder {
    codec_id: Vec<u8>,
    attributes: Vec<u8>,
}

struct Folder {
    coders: Vec<Coder>,
    main_stream: usize,
    output_streams: usize,
}

struct PackInfo {
    pack_pos: u64,
    pack_sizes: Vec<u64>,
}

struct UnpackInfo {
    folders: Vec<Folder>,
    digests: Vec<Option<u32>>,
    unpack_sizes: Vec<u64>,
    main_unpack_size_index: Vec<usize>,
    coder_unpack_sizes: Vec<usize>,
}

struct SubstreamsInfo {
    unpack_sizes: Vec<u64>,
    digests: Vec<Option<u32>>,
}

struct StreamsInfo {
    pack: Option<PackInfo>,
    unpack: Option<UnpackInfo>,
    substreams: Option<SubstreamsInfo>,
}

fn read_pack_info(cursor: &mut Cursor<'_>) -> Result<PackInfo, ExtractError> {
    let pack_pos = cursor.number()?;
    let count = usize::try_from(cursor.number()?)
        .map_err(|_| ExtractError::Invalid("7-Zip pack count is too large".to_owned()))?;
    if !wait_for_id(cursor, SIZE)? {
        return Err(ExtractError::Invalid(
            "7-Zip pack info has no sizes".to_owned(),
        ));
    }
    let mut pack_sizes = Vec::with_capacity(count);
    for _ in 0..count {
        pack_sizes.push(cursor.number()?);
    }
    loop {
        let id = cursor.id()?;
        if id == [END] {
            return Ok(PackInfo {
                pack_pos,
                pack_sizes,
            });
        }
        if id == [CRC] {
            digests(cursor, count)?;
        } else {
            cursor.skip_data()?;
        }
    }
}

fn read_folder(cursor: &mut Cursor<'_>) -> Result<Folder, ExtractError> {
    let count = usize::try_from(cursor.number()?)
        .map_err(|_| ExtractError::Invalid("7-Zip coder count is too large".to_owned()))?;
    let mut coders = Vec::with_capacity(count);
    let mut input_streams = 0usize;
    let mut output_streams = 0usize;
    for _ in 0..count {
        let main = cursor.byte()?;
        if main & 0xc0 != 0 {
            return Err(ExtractError::Invalid(
                "7-Zip coder has unsupported flags".to_owned(),
            ));
        }
        let codec_len = usize::from(main & 0x0f);
        if codec_len > 8 {
            return Err(ExtractError::Invalid(
                "7-Zip coder id is too long".to_owned(),
            ));
        }
        let codec_id = cursor.bytes(codec_len)?.to_vec();
        let mut inputs = 1usize;
        let mut outputs = 1usize;
        if main & 0x10 != 0 {
            inputs = usize::try_from(cursor.number()?)
                .map_err(|_| ExtractError::Invalid("7-Zip stream count".to_owned()))?;
            outputs = usize::try_from(cursor.number()?)
                .map_err(|_| ExtractError::Invalid("7-Zip stream count".to_owned()))?;
        }
        input_streams += inputs;
        output_streams += outputs;
        let attributes = if main & 0x20 != 0 {
            let len = usize::try_from(cursor.number()?)
                .map_err(|_| ExtractError::Invalid("7-Zip attributes too large".to_owned()))?;
            cursor.bytes(len)?.to_vec()
        } else {
            Vec::new()
        };
        coders.push(Coder {
            codec_id,
            attributes,
        });
    }

    let mut main_stream = 0;
    if input_streams != 1 || output_streams != 1 {
        let mut input_used = vec![false; input_streams];
        let mut output_used = vec![false; output_streams];
        let bind_pairs = output_streams - 1;
        for _ in 0..bind_pairs {
            let input = usize::try_from(cursor.number()?)
                .map_err(|_| ExtractError::Invalid("7-Zip bind pair".to_owned()))?;
            let output = usize::try_from(cursor.number()?)
                .map_err(|_| ExtractError::Invalid("7-Zip bind pair".to_owned()))?;
            if input_used.get(input) != Some(&false) || output_used.get(output) != Some(&false) {
                return Err(ExtractError::Invalid(
                    "7-Zip folder has duplicate bind pairs".to_owned(),
                ));
            }
            input_used[input] = true;
            output_used[output] = true;
        }
        let packed = input_streams - bind_pairs;
        if packed != 1 {
            for _ in 0..packed {
                cursor.number()?;
            }
        }
        main_stream = output_used
            .iter()
            .position(|used| !used)
            .ok_or_else(|| ExtractError::Invalid("7-Zip folder has no main stream".to_owned()))?;
    }

    Ok(Folder {
        coders,
        main_stream,
        output_streams,
    })
}

fn read_unpack_info(cursor: &mut Cursor<'_>) -> Result<UnpackInfo, ExtractError> {
    if !wait_for_id(cursor, FOLDER)? {
        return Err(ExtractError::Invalid("7-Zip unpack info".to_owned()));
    }
    let number_folders = usize::try_from(cursor.number()?)
        .map_err(|_| ExtractError::Invalid("7-Zip folder count".to_owned()))?;
    let external = cursor.byte()?;
    let mut folders = Vec::new();
    let mut main_unpack_size_index = Vec::new();
    let mut coder_unpack_sizes = Vec::new();
    let mut output_total = 0usize;
    for _ in 0..number_folders {
        match external {
            0 => {
                let folder = read_folder(cursor)?;
                main_unpack_size_index.push(folder.main_stream);
                coder_unpack_sizes.push(output_total);
                output_total += folder.output_streams;
                folders.push(folder);
            }
            1 => {
                cursor.number()?;
            }
            _ => {
                return Err(ExtractError::Invalid(
                    "7-Zip unpack info has an invalid external flag".to_owned(),
                ));
            }
        }
    }
    if !wait_for_id(cursor, UNPACK_SIZE)? {
        return Err(ExtractError::Invalid(
            "7-Zip unpack info has no sizes".to_owned(),
        ));
    }
    let mut unpack_sizes = Vec::with_capacity(output_total);
    for _ in 0..output_total {
        unpack_sizes.push(cursor.number()?);
    }
    let mut digests_vec = Vec::new();
    loop {
        let id = cursor.id()?;
        if id == [END] {
            break;
        }
        if id == [CRC] {
            digests_vec = digests(cursor, folders.len())?;
        } else {
            cursor.skip_data()?;
        }
    }
    Ok(UnpackInfo {
        folders,
        digests: digests_vec,
        unpack_sizes,
        main_unpack_size_index,
        coder_unpack_sizes,
    })
}

fn folder_unpack_size(unpack: &UnpackInfo, index: usize) -> u64 {
    let stream = unpack.coder_unpack_sizes[index] + unpack.main_unpack_size_index[index];
    unpack.unpack_sizes[stream]
}

fn coder_output_size(unpack: &UnpackInfo, folder: usize, coder: usize) -> u64 {
    let stream = unpack.coder_unpack_sizes[folder] + coder;
    unpack
        .unpack_sizes
        .get(stream)
        .copied()
        .unwrap_or_else(|| folder_unpack_size(unpack, folder))
}

fn read_substreams_info(
    cursor: &mut Cursor<'_>,
    unpack: &UnpackInfo,
) -> Result<SubstreamsInfo, ExtractError> {
    let number_folders = unpack.folders.len();
    let mut unpack_stream_numbers = vec![1usize; number_folders];
    let mut id;
    loop {
        id = cursor.id()?;
        if id == [NUM_UNPACK_STREAM] {
            for slot in &mut unpack_stream_numbers {
                *slot = usize::try_from(cursor.number()?)
                    .map_err(|_| ExtractError::Invalid("7-Zip substream count".to_owned()))?;
            }
        } else if id == [CRC] || id == [SIZE] || id == [END] {
            break;
        } else {
            cursor.skip_data()?;
        }
    }

    let mut unpack_sizes = Vec::new();
    if id == [SIZE] {
        for (folder, count) in unpack_stream_numbers.iter().copied().enumerate() {
            if count == 0 {
                continue;
            }
            let mut total = 0u64;
            for _ in 1..count {
                let size = cursor.number()?;
                unpack_sizes.push(size);
                total += size;
            }
            let folder_size = folder_unpack_size(unpack, folder);
            let last = folder_size.checked_sub(total).ok_or_else(|| {
                ExtractError::Invalid("7-Zip substream sizes exceed the folder size".to_owned())
            })?;
            unpack_sizes.push(last);
        }
        id = cursor.id()?;
    } else {
        for (folder, count) in unpack_stream_numbers.iter().copied().enumerate() {
            if count > 1 {
                return Err(ExtractError::Invalid(
                    "7-Zip substreams are missing sizes".to_owned(),
                ));
            }
            if count == 1 {
                unpack_sizes.push(folder_unpack_size(unpack, folder));
            }
        }
    }

    let mut number_digests = 0usize;
    for (folder, count) in unpack_stream_numbers.iter().copied().enumerate() {
        if count != 1 || unpack.digests.get(folder).copied().flatten().is_none() {
            number_digests += count;
        }
    }

    let mut digests_vec = Vec::new();
    loop {
        if id == [END] {
            break;
        }
        if id == [CRC] {
            let defined = boolean_vector_check_all(cursor, number_digests)?;
            for is_defined in defined {
                let value = cursor.uint32()?;
                digests_vec.push(is_defined.then_some(value));
            }
        } else {
            cursor.skip_data()?;
        }
        id = cursor.id()?;
    }

    Ok(SubstreamsInfo {
        unpack_sizes,
        digests: digests_vec,
    })
}

fn read_streams_info(cursor: &mut Cursor<'_>) -> Result<StreamsInfo, ExtractError> {
    let mut pack = None;
    let mut unpack = None;
    let mut substreams = None;
    let mut id = cursor.id()?;
    if id == [PACK_INFO] {
        pack = Some(read_pack_info(cursor)?);
        id = cursor.id()?;
    }
    if id == [UNPACK_INFO] {
        unpack = Some(read_unpack_info(cursor)?);
        id = cursor.id()?;
    }
    if id == [SUBSTREAMS_INFO] {
        let unpack_ref = unpack.as_ref().ok_or_else(|| {
            ExtractError::Invalid("7-Zip substreams without unpack info".to_owned())
        })?;
        substreams = Some(read_substreams_info(cursor, unpack_ref)?);
    }
    Ok(StreamsInfo {
        pack,
        unpack,
        substreams,
    })
}

fn read_header(cursor: &mut Cursor<'_>) -> Result<StreamsInfo, ExtractError> {
    let mut id = cursor.id()?;
    if id == [ARCHIVE_PROPERTIES] {
        loop {
            let property = cursor.id()?;
            if property == [END] {
                break;
            }
            cursor.skip_data()?;
        }
        id = cursor.id()?;
    }
    if id == [ADD_STREAMS_INFO] {
        return Err(ExtractError::Unsupported(
            "7-Zip additional streams info is not supported".to_owned(),
        ));
    }
    if id != [MAIN_STREAMS_INFO] {
        return Err(ExtractError::Unsupported(
            "7-Zip archive has no main streams info".to_owned(),
        ));
    }
    let streams = read_streams_info(cursor)?;
    Ok(streams)
}

fn decode_lzma(
    attributes: &[u8],
    input: &[u8],
    unpacked_size: u64,
) -> Result<Vec<u8>, ExtractError> {
    if attributes.len() < 5 {
        return Err(ExtractError::Invalid(
            "7-Zip LZMA coder has invalid properties".to_owned(),
        ));
    }
    let packed = u32::from(attributes[0]);
    if packed >= 225 {
        return Err(ExtractError::Invalid(
            "7-Zip LZMA properties are out of range".to_owned(),
        ));
    }
    let lc = packed % 9;
    let rest = packed / 9;
    let lp = rest % 5;
    let pb = rest / 5;
    let dict_size = u32::from_le_bytes(
        attributes[1..5]
            .try_into()
            .expect("four-byte dictionary size"),
    );
    let params = LzmaParams::new(
        LzmaProperties { lc, lp, pb },
        dict_size,
        Some(unpacked_size),
    );
    let mut decoder = LzmaDecoder::new(params, None)
        .map_err(|error| ExtractError::Invalid(format!("7-Zip LZMA header: {error}")))?;
    let mut reader = std::io::Cursor::new(input);
    let mut output = Vec::new();
    decoder
        .decompress(&mut reader, &mut output)
        .map_err(|error| ExtractError::Invalid(format!("7-Zip LZMA data: {error}")))?;
    Ok(output)
}

fn decode_encoded_header(
    streams: &StreamsInfo,
    data: &[u8],
    base: usize,
) -> Result<Vec<u8>, ExtractError> {
    let pack = streams.pack.as_ref().ok_or_else(|| {
        ExtractError::Unsupported("7-Zip encoded header has no pack info".to_owned())
    })?;
    let unpack = streams.unpack.as_ref().ok_or_else(|| {
        ExtractError::Unsupported("7-Zip encoded header has no unpack info".to_owned())
    })?;
    let folder = unpack.folders.first().ok_or_else(|| {
        ExtractError::Unsupported("7-Zip encoded header has no folder".to_owned())
    })?;
    let size = *pack.pack_sizes.first().ok_or_else(|| {
        ExtractError::Unsupported("7-Zip encoded header has no pack size".to_owned())
    })?;
    let start = u64::try_from(base)
        .ok()
        .and_then(|base| base.checked_add(pack.pack_pos))
        .ok_or_else(|| ExtractError::Invalid("7-Zip encoded header offset overflow".to_owned()))?;
    let start = usize::try_from(start).map_err(|_| {
        ExtractError::Unsupported("7-Zip encoded header offset is too large".to_owned())
    })?;
    let size = usize::try_from(size)
        .map_err(|_| ExtractError::Unsupported("7-Zip encoded header is too large".to_owned()))?;
    let input = data
        .get(start..start + size)
        .ok_or_else(|| ExtractError::Invalid("truncated 7-Zip encoded header".to_owned()))?;
    let unpacked_size = folder_unpack_size(unpack, 0);

    match folder.coders.as_slice() {
        [coder] if coder.codec_id == [0x03, 0x01, 0x01] => {
            decode_lzma(&coder.attributes, input, unpacked_size)
        }
        [coder] if coder.codec_id == [0x21] => {
            let mut decoder = Lzma2Decoder::new();
            let mut reader = std::io::Cursor::new(input);
            let mut output = Vec::new();
            decoder
                .decompress(&mut reader, &mut output)
                .map_err(|error| ExtractError::Invalid(format!("7-Zip LZMA2 header: {error}")))?;
            Ok(output)
        }
        [coder] if coder.codec_id == [0x00] => Ok(input.to_vec()),
        _ => Err(ExtractError::Unsupported(
            "unsupported 7-Zip encoded header coder".to_owned(),
        )),
    }
}

fn archive_streams(data: &[u8]) -> Result<(StreamsInfo, usize), ExtractError> {
    let (data, outer) = if data.starts_with(SIGNATURE) {
        (data, 0)
    } else {
        let offset = data
            .windows(SIGNATURE.len())
            .position(|window| window == SIGNATURE)
            .ok_or_else(|| ExtractError::Unsupported("no 7-Zip signature found".to_owned()))?;
        (&data[offset..], offset)
    };
    if data.len() < 32 {
        return Err(ExtractError::Unsupported(
            "truncated 7-Zip archive".to_owned(),
        ));
    }
    let mut cursor = Cursor::new(data);
    cursor.position = 8;
    cursor.uint32()?;
    let next_header_offset = cursor.uint64()?;
    let next_header_size = cursor.uint64()?;
    cursor.uint32()?;

    let header_offset = usize::try_from(32 + next_header_offset)
        .map_err(|_| ExtractError::Invalid("7-Zip header offset".to_owned()))?;
    let header_size = usize::try_from(next_header_size)
        .map_err(|_| ExtractError::Invalid("7-Zip header size".to_owned()))?;
    let header = data
        .get(header_offset..header_offset + header_size)
        .ok_or_else(|| ExtractError::Invalid("truncated 7-Zip header".to_owned()))?;
    let mut header_cursor = Cursor::new(header);
    let id = header_cursor.id()?;
    let streams = if id == [HEADER] {
        read_header(&mut header_cursor)?
    } else if id == [ENCODED_HEADER] {
        let encoded = read_streams_info(&mut header_cursor)?;
        let encrypted = encoded.unpack.as_ref().is_some_and(|unpack| {
            unpack
                .folders
                .iter()
                .any(|folder| folder.coders.iter().any(|coder| coder.codec_id == AES))
        });
        if encrypted {
            encoded
        } else {
            let decoded = decode_encoded_header(&encoded, data, 32)?;
            let mut decoded_cursor = Cursor::new(&decoded);
            let decoded_id = decoded_cursor.id()?;
            if decoded_id != [HEADER] {
                return Err(ExtractError::Unsupported(
                    "7-Zip encoded header is not a header".to_owned(),
                ));
            }
            read_header(&mut decoded_cursor)?
        }
    } else {
        return Err(ExtractError::Invalid(
            "7-Zip header has an unknown type".to_owned(),
        ));
    };
    Ok((streams, outer + 32))
}

struct AesAttributes {
    cycles: u8,
    salt_size: u8,
    salt: Vec<u8>,
    iv_size: u8,
    iv: [u8; 16],
}

fn aes_attributes(attributes: &[u8]) -> Result<AesAttributes, ExtractError> {
    let first = *attributes
        .first()
        .ok_or_else(|| ExtractError::Invalid("7-Zip AES coder has no properties".to_owned()))?;
    let cycles = first & 0x3f;
    if first & 0xc0 == 0 {
        return Ok(AesAttributes {
            cycles,
            salt_size: 0,
            salt: Vec::new(),
            iv_size: 16,
            iv: [0; 16],
        });
    }
    let second = *attributes
        .get(1)
        .ok_or_else(|| ExtractError::Invalid("7-Zip AES properties are truncated".to_owned()))?;
    let salt_len = usize::from((first >> 7) & 1) + usize::from(second >> 4);
    let iv_len = usize::from((first >> 6) & 1) + usize::from(second & 0x0f);
    let salt_start = 2;
    let salt = attributes
        .get(salt_start..salt_start + salt_len)
        .ok_or_else(|| ExtractError::Invalid("7-Zip AES salt is truncated".to_owned()))?
        .to_vec();
    let iv_start = salt_start + salt_len;
    let iv = attributes
        .get(iv_start..iv_start + iv_len)
        .ok_or_else(|| ExtractError::Invalid("7-Zip AES IV is truncated".to_owned()))?;
    let mut padded = [0u8; 16];
    padded[..iv.len()].copy_from_slice(iv);
    Ok(AesAttributes {
        cycles,
        salt_size: salt_len as u8,
        salt,
        iv_size: iv_len as u8,
        iv: padded,
    })
}

fn compression_type(codec: &[u8]) -> Option<u8> {
    match codec {
        [0x03, 0x01, 0x01] => Some(1),
        [0x21] => Some(2),
        [0x03, 0x04, 0x01] => Some(3),
        [0x03, 0x03, 0x01, 0x03] => Some(4),
        [0x03, 0x03, 0x01, 0x1b] => Some(5),
        [0x04, 0x02, 0x02] => Some(6),
        [0x04, 0x01, 0x08] => Some(7),
        _ => None,
    }
}

fn hashes(data: &[u8]) -> Result<Vec<SevenZip>, ExtractError> {
    let (streams, base) = archive_streams(data)?;
    let pack = streams
        .pack
        .ok_or_else(|| ExtractError::Unsupported("7-Zip archive has no pack info".to_owned()))?;
    let unpack = streams
        .unpack
        .ok_or_else(|| ExtractError::Unsupported("7-Zip archive has no unpack info".to_owned()))?;
    let substreams = streams.substreams;
    let mut offsets = Vec::with_capacity(pack.pack_sizes.len());
    let mut offset = u64::try_from(base).expect("base fits");
    offset = offset
        .checked_add(pack.pack_pos)
        .ok_or_else(|| ExtractError::Invalid("7-Zip data offset overflow".to_owned()))?;
    for size in &pack.pack_sizes {
        offsets.push(offset);
        offset = offset
            .checked_add(*size)
            .ok_or_else(|| ExtractError::Invalid("7-Zip data offset overflow".to_owned()))?;
    }

    let mut hashes = Vec::new();
    let mut pack_index = 0usize;
    for (folder_index, folder) in unpack.folders.iter().enumerate() {
        let aes = folder.coders.iter().position(|coder| coder.codec_id == AES);
        let Some(aes_index) = aes else {
            pack_index += 1;
            continue;
        };
        let data_size = *pack
            .pack_sizes
            .get(pack_index)
            .ok_or_else(|| ExtractError::Invalid("7-Zip pack index".to_owned()))?;
        let data_offset = offsets[pack_index];
        let data_size_usize = usize::try_from(data_size)
            .map_err(|_| ExtractError::Unsupported("7-Zip stream is too large".to_owned()))?;
        let data_offset_usize = usize::try_from(data_offset).map_err(|_| {
            ExtractError::Unsupported("7-Zip stream offset is too large".to_owned())
        })?;
        let ciphertext = data
            .get(data_offset_usize..data_offset_usize + data_size_usize)
            .ok_or_else(|| ExtractError::Invalid("truncated 7-Zip stream".to_owned()))?
            .to_vec();

        let crc = unpack
            .digests
            .get(folder_index)
            .copied()
            .flatten()
            .or_else(|| {
                substreams
                    .as_ref()
                    .and_then(|substreams| substreams.digests.get(folder_index).copied().flatten())
            })
            .ok_or_else(|| {
                ExtractError::Unsupported("7-Zip encrypted stream has no CRC checksum".to_owned())
            })?;
        let folder_size = folder_unpack_size(&unpack, folder_index);
        let unpacked_size = coder_output_size(&unpack, folder_index, aes_index);
        let attributes = aes_attributes(&folder.coders[aes_index].attributes)?;

        let mut data_type = 0u8;
        let mut crc_len = 0u64;
        let mut compression_attributes = Vec::new();
        if let Some(coder) = folder.coders.get(aes_index + 1) {
            if let Some(kind) = compression_type(&coder.codec_id) {
                data_type = kind;
                crc_len = substreams
                    .as_ref()
                    .and_then(|substreams| substreams.unpack_sizes.first().copied())
                    .unwrap_or(folder_size);
                compression_attributes = coder.attributes.clone();
            }
        }

        let mut data_field = crate::format::hex(&ciphertext);
        if data_type != 0 && data_type != 128 {
            data_field.push('$');
            data_field.push_str(&crc_len.to_string());
            data_field.push('$');
            data_field.push_str(&crate::format::hex(&compression_attributes));
        }

        hashes.push(SevenZip {
            data_type,
            cycles_power: attributes.cycles,
            salt_size: attributes.salt_size,
            salt: crate::format::hex(&attributes.salt),
            iv_size: attributes.iv_size,
            iv: crate::format::hex(attributes.iv),
            crc,
            data_size: u32::try_from(data_size).unwrap_or(u32::MAX),
            unpacked_size: u32::try_from(unpacked_size).unwrap_or(u32::MAX),
            data: data_field,
        });
        pack_index += 1;
    }
    Ok(hashes)
}

impl Extractor for SevenZipExtractor {
    fn slug(&self) -> &'static str {
        SevenZip::SLUG
    }

    fn probe(&self, artifact: &Artifact) -> Probe {
        let data = match artifact.primary().read_all() {
            Ok(data) => data,
            Err(error) => return Probe::maybe(format!("cannot read artifact: {error}")),
        };
        match hashes(&data) {
            Ok(hashes) if !hashes.is_empty() => Probe::yes("7-Zip AES coder"),
            _ => Probe::No,
        }
    }

    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError> {
        let data = artifact.primary().read_all().map_err(|error| {
            ExtractError::Invalid(format!("cannot read {}: {error}", artifact.label()))
        })?;
        let hashes = hashes(&data)?;
        if hashes.is_empty() {
            return Err(ExtractError::Unsupported(
                "no AES-encrypted 7-Zip streams found".to_owned(),
            ));
        }
        Ok(hashes
            .into_iter()
            .map(|hash| Box::new(hash) as Box<dyn HashValue>)
            .collect())
    }
}
