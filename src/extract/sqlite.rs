//! Minimal read-only scan of SQLite table pages for text values.
//!
//! Only what extractors need to find embedded configuration blobs: the leaf
//! cells of table b-trees, including payloads stored on overflow pages.

const HEADER: &[u8] = b"SQLite format 3\0";

pub fn is_sqlite(data: &[u8]) -> bool {
    data.starts_with(HEADER)
}

pub fn text_values(data: &[u8]) -> Vec<String> {
    let mut values = Vec::new();
    if !is_sqlite(data) {
        return values;
    }
    let Some(page_size) = page_size(data) else {
        return values;
    };
    let reserved = data.get(20).copied().unwrap_or(0) as usize;
    let usable = page_size.saturating_sub(reserved);
    if usable < 480 {
        return values;
    }
    for page in 0..data.len() / page_size {
        let start = page * page_size;
        let header = if page == 0 { 100 } else { 0 };
        scan_page(data, start, header, page_size, usable, &mut values);
    }
    values
}

fn page_size(data: &[u8]) -> Option<usize> {
    let raw = u16::from_be_bytes([*data.get(16)?, *data.get(17)?]);
    Some(if raw == 1 { 65536 } else { raw as usize })
}

fn scan_page(
    data: &[u8],
    start: usize,
    header: usize,
    page_size: usize,
    usable: usize,
    values: &mut Vec<String>,
) {
    let Some(page) = data.get(start..start + page_size) else {
        return;
    };
    if page.get(header) != Some(&0x0d) {
        return;
    }
    let Some(cells) = read_u16(page, header + 3) else {
        return;
    };
    let cells = cells as usize;
    let pointer = header + 8;
    if cells == 0 || cells > 4096 || pointer + cells * 2 > page_size {
        return;
    }
    for index in 0..cells {
        let Some(offset) = read_u16(page, pointer + index * 2) else {
            continue;
        };
        let offset = offset as usize;
        if offset < pointer + cells * 2 || offset >= page_size {
            continue;
        }
        let Some(payload) = payload(data, page, offset, page_size, usable) else {
            continue;
        };
        for value in record(&payload) {
            if let Ok(text) = std::str::from_utf8(value) {
                values.push(text.to_owned());
            }
        }
    }
}

fn payload(
    data: &[u8],
    page: &[u8],
    offset: usize,
    page_size: usize,
    usable: usize,
) -> Option<Vec<u8>> {
    let (length, mut pos) = varint(page.get(offset..)?)?;
    let (_, size) = varint(page.get(offset + pos..)?)?;
    pos += size;
    let length = length as usize;
    let max_local = usable - 35;
    let min_local = (usable - 12) * 32 / 255 - 23;
    let local = if length <= max_local {
        length
    } else {
        (min_local + (length - min_local) % (usable - 4)).min(max_local)
    };
    let start = offset + pos;
    let mut payload = page.get(start..start + local)?.to_vec();
    if local == length {
        return Some(payload);
    }
    let mut next = read_u32(page, start + local)? as usize;
    while payload.len() < length {
        if next == 0 {
            return None;
        }
        let start = (next - 1) * page_size;
        let page = data.get(start..start + page_size)?;
        next = read_u32(page, 0)? as usize;
        let take = (length - payload.len()).min(usable - 4);
        payload.extend_from_slice(page.get(4..4 + take)?);
    }
    Some(payload)
}

fn record(payload: &[u8]) -> Vec<&[u8]> {
    let Some((header, mut pos)) = varint(payload) else {
        return Vec::new();
    };
    let header = header as usize;
    if header > payload.len() {
        return Vec::new();
    }
    let mut types = Vec::new();
    while pos < header {
        let Some((kind, size)) = varint(&payload[pos..]) else {
            return Vec::new();
        };
        pos += size;
        types.push(kind);
    }
    let mut values = Vec::new();
    let mut body = header;
    for kind in types {
        let size = match kind {
            0 | 8 | 9 => 0,
            1 => 1,
            2 => 2,
            3 => 3,
            4 => 4,
            5 => 6,
            6 | 7 => 8,
            10 | 11 => return Vec::new(),
            kind if kind >= 13 => (kind - 13) / 2,
            kind if kind >= 12 => (kind - 12) / 2,
            _ => return Vec::new(),
        } as usize;
        let Some(value) = payload.get(body..body + size) else {
            return Vec::new();
        };
        if kind >= 13 && kind % 2 == 1 {
            values.push(value);
        }
        body += size;
    }
    values
}

fn varint(data: &[u8]) -> Option<(u64, usize)> {
    let mut value = 0u64;
    for (index, byte) in data.iter().take(9).enumerate() {
        if index == 8 {
            value = (value << 8) | *byte as u64;
            return Some((value, 9));
        }
        value = (value << 7) | (byte & 0x7f) as u64;
        if byte & 0x80 == 0 {
            return Some((value, index + 1));
        }
    }
    None
}

fn read_u16(data: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_be_bytes([
        *data.get(offset)?,
        *data.get(offset + 1)?,
    ]))
}

fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_be_bytes([
        *data.get(offset)?,
        *data.get(offset + 1)?,
        *data.get(offset + 2)?,
        *data.get(offset + 3)?,
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn database(text: &str) -> Vec<u8> {
        let mut page = vec![0u8; 512];
        page[..HEADER.len()].copy_from_slice(HEADER);
        page[16..18].copy_from_slice(&512u16.to_be_bytes());
        page[100] = 0x0d;
        page[103..105].copy_from_slice(&1u16.to_be_bytes());
        let mut cell = Vec::new();
        let body = text.as_bytes();
        let payload = (body.len() + 2) as u64;
        cell.extend(varint_encode(payload));
        cell.push(1);
        cell.push(2);
        cell.push((13 + (body.len() as u64) * 2) as u8);
        cell.extend_from_slice(body);
        let offset = 512 - cell.len();
        page[108..110].copy_from_slice(&(offset as u16).to_be_bytes());
        page[offset..].copy_from_slice(&cell);
        page
    }

    fn varint_encode(mut value: u64) -> Vec<u8> {
        let mut out = vec![(value & 0x7f) as u8];
        value >>= 7;
        while value > 0 {
            out.push((value & 0x7f) as u8 | 0x80);
            value >>= 7;
        }
        out.reverse();
        out
    }

    #[test]
    fn reads_text_from_leaf_cells() {
        let page = database("iterations=1000;payload");
        assert_eq!(text_values(&page), vec!["iterations=1000;payload"]);
    }

    #[test]
    fn ignores_non_sqlite_data() {
        assert!(text_values(b"not a database").is_empty());
    }
}
