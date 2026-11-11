//! Virtual disk containers that wrap a logical disk in a larger file.

use byteorder::{BigEndian, ByteOrder, LittleEndian};

use super::{Artifact, ExtractError, ReadAt};

const VDI_MAGIC: u32 = 0xBEDA_107F;
const VDI_VERSION: u32 = 0x0001_0001;
const VDI_SIGNATURE_OFFSET: usize = 0x40;
const QCOW2_MAGIC: [u8; 4] = *b"QFI\xfb";
const QCOW2_L2_COMPRESSED: u64 = 1 << 62;
const QCOW2_OFFSET_MASK: u64 = 0x00ff_ffff_ffff_fe00;

pub enum Container<'a> {
    Raw(&'a dyn ReadAt),
    Vdi(Vdi<'a>),
    Qcow2(Qcow2<'a>),
}

impl Container<'_> {
    /// Logical ranges that contain stored bytes rather than sparse holes.
    ///
    /// Sparse regions always read back as zeros, so callers that search for a
    /// signature can skip them without changing the result.
    #[must_use]
    pub fn data_ranges(&self) -> Vec<(u64, u64)> {
        match self {
            Self::Raw(source) => vec![(0, source.len())],
            Self::Vdi(source) => source.data_ranges(),
            Self::Qcow2(source) => source.data_ranges(),
        }
    }

    pub fn open(artifact: &Artifact) -> Result<Container<'_>, ExtractError> {
        let source = artifact.primary();
        let mut magic = [0u8; 4];
        if source.read_at(0, &mut magic).unwrap_or(0) == 4 && magic == QCOW2_MAGIC {
            return Qcow2::open(source).map(Container::Qcow2);
        }
        let mut signature = [0u8; 4];
        if source
            .read_at(VDI_SIGNATURE_OFFSET as u64, &mut signature)
            .unwrap_or(0)
            == 4
            && u32::from_le_bytes(signature) == VDI_MAGIC
        {
            return Vdi::open(source).map(Container::Vdi);
        }
        Ok(Container::Raw(source))
    }
}

impl ReadAt for Container<'_> {
    fn len(&self) -> u64 {
        match self {
            Self::Raw(source) => source.len(),
            Self::Vdi(source) => source.len(),
            Self::Qcow2(source) => source.len(),
        }
    }

    fn read_at(&self, offset: u64, out: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Raw(source) => source.read_at(offset, out),
            Self::Vdi(source) => source.read_at(offset, out),
            Self::Qcow2(source) => source.read_at(offset, out),
        }
    }
}

pub struct Vdi<'a> {
    source: &'a dyn ReadAt,
    block_size: u64,
    virtual_size: u64,
    blocks: Vec<Option<u64>>,
}

impl<'a> Vdi<'a> {
    fn open(source: &'a dyn ReadAt) -> Result<Self, ExtractError> {
        let mut header = [0u8; 0x188];
        source
            .read_exact_at(0, &mut header)
            .map_err(|_| ExtractError::Invalid("truncated VDI header".to_owned()))?;
        if LittleEndian::read_u32(&header[VDI_SIGNATURE_OFFSET..]) != VDI_MAGIC {
            return Err(ExtractError::Unsupported("not a VDI image".to_owned()));
        }
        if LittleEndian::read_u32(&header[0x44..]) != VDI_VERSION {
            return Err(ExtractError::Unsupported(
                "unsupported VDI version".to_owned(),
            ));
        }
        if LittleEndian::read_u32(&header[0x4c..]) != 1 {
            return Err(ExtractError::Unsupported(
                "only dynamic VDI images are supported".to_owned(),
            ));
        }
        let block_map_offset = u64::from(LittleEndian::read_u32(&header[0x154..]));
        let data_offset = u64::from(LittleEndian::read_u32(&header[0x158..]));
        let virtual_size = LittleEndian::read_u64(&header[0x170..]);
        let block_size = u64::from(LittleEndian::read_u32(&header[0x178..]));
        let blocks_in_image = LittleEndian::read_u32(&header[0x180..]);
        if block_size == 0 || blocks_in_image == 0 {
            return Err(ExtractError::Invalid("invalid VDI block layout".to_owned()));
        }
        let mut raw = vec![0u8; blocks_in_image as usize * 4];
        source
            .read_exact_at(block_map_offset, &mut raw)
            .map_err(|_| ExtractError::Invalid("truncated VDI block map".to_owned()))?;
        let blocks = raw
            .chunks_exact(4)
            .map(|chunk| {
                let value = LittleEndian::read_u32(chunk);
                (value != u32::MAX).then(|| data_offset + u64::from(value) * block_size)
            })
            .collect();
        Ok(Self {
            source,
            block_size,
            virtual_size,
            blocks,
        })
    }

    fn data_ranges(&self) -> Vec<(u64, u64)> {
        logical_ranges(
            self.block_size,
            self.virtual_size,
            self.blocks.iter().map(Option::is_some),
        )
    }
}

impl ReadAt for Vdi<'_> {
    fn len(&self) -> u64 {
        self.virtual_size
    }

    fn read_at(&self, offset: u64, out: &mut [u8]) -> std::io::Result<usize> {
        if offset >= self.virtual_size {
            return Ok(0);
        }
        let length = out.len().min((self.virtual_size - offset) as usize);
        let mut done = 0;
        while done < length {
            let position = offset + done as u64;
            let block = (position / self.block_size) as usize;
            let inside = position % self.block_size;
            let chunk = ((self.block_size - inside) as usize).min(length - done);
            match self.blocks.get(block).copied().flatten() {
                Some(file_offset) => {
                    let read = self
                        .source
                        .read_at(file_offset + inside, &mut out[done..done + chunk])?;
                    if read == 0 {
                        break;
                    }
                    done += read;
                }
                None => {
                    out[done..done + chunk].fill(0);
                    done += chunk;
                }
            }
        }
        Ok(done)
    }
}

pub struct Qcow2<'a> {
    source: &'a dyn ReadAt,
    cluster_size: u64,
    virtual_size: u64,
    l2: Vec<Option<Vec<u64>>>,
    l2_entries: u64,
}

impl<'a> Qcow2<'a> {
    fn open(source: &'a dyn ReadAt) -> Result<Self, ExtractError> {
        let mut header = [0u8; 112];
        source
            .read_exact_at(0, &mut header)
            .map_err(|_| ExtractError::Invalid("truncated QCOW2 header".to_owned()))?;
        if header[..4] != QCOW2_MAGIC {
            return Err(ExtractError::Unsupported("not a QCOW2 image".to_owned()));
        }
        let version = BigEndian::read_u32(&header[4..]);
        if !matches!(version, 2 | 3) {
            return Err(ExtractError::Unsupported(format!(
                "unsupported QCOW2 version {version}"
            )));
        }
        let backing_offset = BigEndian::read_u64(&header[8..]);
        if backing_offset != 0 {
            return Err(ExtractError::Unsupported(
                "QCOW2 backing files are not supported".to_owned(),
            ));
        }
        let cluster_bits = BigEndian::read_u32(&header[20..]);
        if !(9..=21).contains(&cluster_bits) {
            return Err(ExtractError::Unsupported(
                "unsupported QCOW2 cluster size".to_owned(),
            ));
        }
        if BigEndian::read_u32(&header[32..]) != 0 {
            return Err(ExtractError::Unsupported(
                "encrypted QCOW2 images are not supported".to_owned(),
            ));
        }
        let virtual_size = BigEndian::read_u64(&header[24..]);
        let l1_size = BigEndian::read_u32(&header[36..]);
        let l1_offset = BigEndian::read_u64(&header[40..]);
        let cluster_size = 1u64 << cluster_bits;
        let l2_entries = cluster_size / 8;
        if l1_size == 0 || l1_size > 1_000_000 {
            return Err(ExtractError::Unsupported(
                "unsupported QCOW2 L1 table size".to_owned(),
            ));
        }
        let mut l1 = vec![0u8; l1_size as usize * 8];
        source
            .read_exact_at(l1_offset, &mut l1)
            .map_err(|_| ExtractError::Invalid("truncated QCOW2 L1 table".to_owned()))?;
        let mut l2 = Vec::with_capacity(l1_size as usize);
        for entry in l1.chunks_exact(8) {
            let offset = BigEndian::read_u64(entry) & QCOW2_OFFSET_MASK;
            if offset == 0 {
                l2.push(None);
                continue;
            }
            let mut table = vec![0u8; cluster_size as usize];
            source
                .read_exact_at(offset, &mut table)
                .map_err(|_| ExtractError::Invalid("truncated QCOW2 L2 table".to_owned()))?;
            l2.push(Some(
                table
                    .chunks_exact(8)
                    .map(BigEndian::read_u64)
                    .collect::<Vec<_>>(),
            ));
        }
        Ok(Self {
            source,
            cluster_size,
            virtual_size,
            l2,
            l2_entries,
        })
    }

    fn data_ranges(&self) -> Vec<(u64, u64)> {
        let clusters = usize::try_from(self.virtual_size.div_ceil(self.cluster_size)).unwrap_or(0);
        let mut mapped = vec![false; clusters];
        for (level, table) in self.l2.iter().enumerate() {
            let Some(table) = table else {
                continue;
            };
            for (index, entry) in table.iter().enumerate() {
                if *entry == 0 {
                    continue;
                }
                let cluster = level
                    .saturating_mul(self.l2_entries as usize)
                    .saturating_add(index);
                if let Some(slot) = mapped.get_mut(cluster) {
                    *slot = true;
                }
            }
        }
        logical_ranges(self.cluster_size, self.virtual_size, mapped.into_iter())
    }
}

impl ReadAt for Qcow2<'_> {
    fn len(&self) -> u64 {
        self.virtual_size
    }

    fn read_at(&self, offset: u64, out: &mut [u8]) -> std::io::Result<usize> {
        if offset >= self.virtual_size {
            return Ok(0);
        }
        let length = out.len().min((self.virtual_size - offset) as usize);
        let mut done = 0;
        while done < length {
            let position = offset + done as u64;
            let cluster = position / self.cluster_size;
            let inside = position % self.cluster_size;
            let chunk = ((self.cluster_size - inside) as usize).min(length - done);
            let l1_index = (cluster / self.l2_entries) as usize;
            let l2_index = (cluster % self.l2_entries) as usize;
            let entry = self
                .l2
                .get(l1_index)
                .and_then(|table| table.as_ref())
                .and_then(|table| table.get(l2_index))
                .copied()
                .unwrap_or(0);
            if entry & QCOW2_L2_COMPRESSED != 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "compressed QCOW2 clusters are not supported",
                ));
            }
            let file_offset = entry & QCOW2_OFFSET_MASK;
            if file_offset == 0 {
                out[done..done + chunk].fill(0);
                done += chunk;
            } else {
                let read = self
                    .source
                    .read_at(file_offset + inside, &mut out[done..done + chunk])?;
                if read == 0 {
                    break;
                }
                done += read;
            }
        }
        Ok(done)
    }
}

fn logical_ranges(
    block_size: u64,
    virtual_size: u64,
    mapped: impl Iterator<Item = bool>,
) -> Vec<(u64, u64)> {
    let mut ranges = Vec::new();
    let mut start = None;
    for (index, present) in mapped.enumerate() {
        let offset = (index as u64).saturating_mul(block_size);
        if offset >= virtual_size {
            break;
        }
        match (present, start) {
            (true, None) => start = Some(offset),
            (false, Some(begin)) => {
                ranges.push((begin, offset - begin));
                start = None;
            }
            _ => {}
        }
    }
    if let Some(begin) = start {
        ranges.push((begin, virtual_size - begin));
    }
    ranges
}

pub struct Window<'a> {
    source: &'a dyn ReadAt,
    offset: u64,
    len: u64,
}

impl<'a> Window<'a> {
    #[must_use]
    pub fn new(source: &'a dyn ReadAt, offset: u64, len: u64) -> Self {
        Self {
            source,
            offset,
            len: len.min(source.len().saturating_sub(offset)),
        }
    }
}

impl ReadAt for Window<'_> {
    fn len(&self) -> u64 {
        self.len
    }

    fn read_at(&self, offset: u64, out: &mut [u8]) -> std::io::Result<usize> {
        if offset >= self.len {
            return Ok(0);
        }
        let length = out.len().min((self.len - offset) as usize);
        self.source
            .read_at(self.offset + offset, &mut out[..length])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extract::Artifact;

    fn vdi(payload: &[u8; 512]) -> Vec<u8> {
        let mut data = vec![0u8; 0x2000];
        data[0x40..0x44].copy_from_slice(&VDI_MAGIC.to_le_bytes());
        data[0x44..0x48].copy_from_slice(&VDI_VERSION.to_le_bytes());
        data[0x4c..0x50].copy_from_slice(&1u32.to_le_bytes());
        data[0x154..0x158].copy_from_slice(&0x200u32.to_le_bytes());
        data[0x158..0x15c].copy_from_slice(&0x1000u32.to_le_bytes());
        data[0x170..0x178].copy_from_slice(&0x1000u64.to_le_bytes());
        data[0x178..0x17c].copy_from_slice(&0x1000u32.to_le_bytes());
        data[0x180..0x184].copy_from_slice(&1u32.to_le_bytes());
        data[0x200..0x204].copy_from_slice(&0u32.to_le_bytes());
        data[0x1000..0x1200].copy_from_slice(payload);
        data
    }

    #[test]
    fn reads_vdi_blocks() {
        let mut payload = [0u8; 512];
        payload[..4].copy_from_slice(b"TEST");
        let artifact = Artifact::from_bytes("test.vdi", vdi(&payload));
        let container = Container::open(&artifact).expect("open VDI");
        assert_eq!(container.len(), 0x1000);
        let mut out = [0u8; 8];
        assert_eq!(container.read_at(0, &mut out).unwrap(), 8);
        assert_eq!(&out[..4], b"TEST");
        assert_eq!(out[4..], [0; 4]);
        assert_eq!(container.data_ranges(), vec![(0, 0x1000)]);
    }

    #[test]
    fn vdi_data_ranges_skip_unmapped_blocks() {
        let mut data = vec![0u8; 0x3000];
        data[0x40..0x44].copy_from_slice(&VDI_MAGIC.to_le_bytes());
        data[0x44..0x48].copy_from_slice(&VDI_VERSION.to_le_bytes());
        data[0x4c..0x50].copy_from_slice(&1u32.to_le_bytes());
        data[0x154..0x158].copy_from_slice(&0x200u32.to_le_bytes());
        data[0x158..0x15c].copy_from_slice(&0x1000u32.to_le_bytes());
        data[0x170..0x178].copy_from_slice(&0x4000u64.to_le_bytes());
        data[0x178..0x17c].copy_from_slice(&0x1000u32.to_le_bytes());
        data[0x180..0x184].copy_from_slice(&4u32.to_le_bytes());
        for block in 0..4 {
            let value = match block {
                0 => 0u32,
                3 => 1u32,
                _ => u32::MAX,
            };
            data[0x200 + block * 4..0x204 + block * 4].copy_from_slice(&value.to_le_bytes());
        }
        let artifact = Artifact::from_bytes("sparse.vdi", data);
        let container = Container::open(&artifact).expect("open VDI");
        assert_eq!(container.data_ranges(), vec![(0, 0x1000), (0x3000, 0x1000)]);
        let mut out = [0xffu8; 4];
        assert_eq!(container.read_at(0x1000, &mut out).unwrap(), 4);
        assert_eq!(out, [0; 4]);
    }

    fn qcow2(payload: &[u8; 512]) -> Vec<u8> {
        let mut data = vec![0u8; 0x4000];
        data[..4].copy_from_slice(&QCOW2_MAGIC);
        data[4..8].copy_from_slice(&3u32.to_be_bytes());
        data[20..24].copy_from_slice(&12u32.to_be_bytes());
        data[24..32].copy_from_slice(&0x1000u64.to_be_bytes());
        data[36..40].copy_from_slice(&1u32.to_be_bytes());
        data[40..48].copy_from_slice(&0x1000u64.to_be_bytes());
        data[0x1000..0x1008].copy_from_slice(&0x2000u64.to_be_bytes());
        data[0x2000..0x2008].copy_from_slice(&0x3000u64.to_be_bytes());
        data[0x3000..0x3200].copy_from_slice(payload);
        data
    }

    #[test]
    fn reads_qcow2_clusters() {
        let mut payload = [0u8; 512];
        payload[..4].copy_from_slice(b"TEST");
        let artifact = Artifact::from_bytes("test.qcow2", qcow2(&payload));
        let container = Container::open(&artifact).expect("open QCOW2");
        assert_eq!(container.len(), 0x1000);
        let mut out = [0u8; 8];
        assert_eq!(container.read_at(0, &mut out).unwrap(), 8);
        assert_eq!(&out[..4], b"TEST");
        assert_eq!(out[4..], [0; 4]);
        assert_eq!(container.data_ranges(), vec![(0, 0x1000)]);
    }

    #[test]
    fn qcow2_data_ranges_skip_unmapped_clusters() {
        let mut data = vec![0u8; 0x5000];
        data[..4].copy_from_slice(&QCOW2_MAGIC);
        data[4..8].copy_from_slice(&3u32.to_be_bytes());
        data[20..24].copy_from_slice(&12u32.to_be_bytes());
        data[24..32].copy_from_slice(&0x4000u64.to_be_bytes());
        data[36..40].copy_from_slice(&1u32.to_be_bytes());
        data[40..48].copy_from_slice(&0x1000u64.to_be_bytes());
        data[0x1000..0x1008].copy_from_slice(&0x2000u64.to_be_bytes());
        for (cluster, entry) in [(0, 0x3000u64), (3, 0x4000u64)] {
            let start = 0x2000 + cluster * 8;
            data[start..start + 8].copy_from_slice(&entry.to_be_bytes());
        }
        let artifact = Artifact::from_bytes("sparse.qcow2", data);
        let container = Container::open(&artifact).expect("open QCOW2");
        assert_eq!(container.data_ranges(), vec![(0, 0x1000), (0x3000, 0x1000)]);
    }
}
