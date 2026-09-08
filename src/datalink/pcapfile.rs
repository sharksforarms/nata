/*!
Packet interface for reading PCAP and PCAPNG files and writing PCAP files.
*/
use crate::{
    datalink::{
        error::DataLinkError, InterfaceMetadata, InterfaceReader, InterfaceWriter,
        PacketInterfaceRead, PacketInterfaceWrite, PacketRead, PacketWrite,
    },
    layer::{ether::Ether, raw::Raw},
    packet::{Packet, PacketParser},
};
use core::convert::{TryFrom, TryInto};
use flate2::read::GzDecoder;
use pcap_file::{
    pcap::{PcapPacket, PcapReader, PcapWriter},
    pcapng::{Block, PcapNgReader},
    DataLink,
};
use std::time::{SystemTime, UNIX_EPOCH};
use std::{
    fs::File,
    io::{Cursor, Read},
};

/// PCAP/PCAPNG file based interface.
pub struct PcapFile {}

/// A packet record read from a PCAP or PCAPNG capture.
#[derive(Debug)]
pub struct CapturePacket {
    /// The link-layer type associated with the packet.
    pub link_type: DataLink,
    /// The original packet length before capture truncation.
    pub original_len: u32,
    /// The captured packet bytes.
    pub data: Vec<u8>,
}

enum ReaderKind {
    Pcap {
        reader: PcapReader<Box<dyn Read>>,
        link_type: DataLink,
    },
    PcapNg {
        reader: PcapNgReader<Box<dyn Read>>,
        interfaces: Vec<PcapNgInterface>,
    },
}

#[derive(Clone, Copy)]
struct PcapNgInterface {
    link_type: DataLink,
    snaplen: u32,
}

/// PCAP/PCAPNG file reader.
pub struct PcapFileReader {
    filename: String,
    packet_parser: PacketParser,
    reader: ReaderKind,
}

/// Pcap file writer
pub struct PcapFileWriter {
    writer: PcapWriter<File>,
}

impl PacketInterfaceRead for PcapFile {
    type Reader = PcapFileReader;

    fn init(filename: &str) -> Result<InterfaceReader<Self::Reader>, DataLinkError>
    where
        Self: Sized,
    {
        <Self as PacketInterfaceRead>::init_with_parser(filename, PacketParser::new())
    }

    fn init_with_parser(
        filename: &str,
        packet_parser: PacketParser,
    ) -> Result<InterfaceReader<Self::Reader>, DataLinkError>
    where
        Self: Sized,
    {
        let reader = PcapFileReader::new(filename, packet_parser)?;

        Ok(InterfaceReader {
            reader,
            metadata: InterfaceMetadata { mac_address: None },
        })
    }
}

impl PacketInterfaceWrite for PcapFile {
    type Writer = PcapFileWriter;

    fn init(filename: &str) -> Result<super::InterfaceWriter<Self::Writer>, DataLinkError>
    where
        Self: Sized,
    {
        let file_in = File::create(filename)?;
        let writer = PcapWriter::new(file_in)?;

        Ok(InterfaceWriter {
            writer: PcapFileWriter { writer },
            metadata: InterfaceMetadata { mac_address: None },
        })
    }
}

impl PcapFileReader {
    /// Open a PCAP or PCAPNG file for reading.
    pub fn new(filename: &str, packet_parser: PacketParser) -> Result<Self, DataLinkError> {
        let source = source_with_optional_gzip(File::open(filename)?)?;
        Self::from_source(filename, source, packet_parser)
    }

    #[cfg(test)]
    fn from_bytes(
        filename: &str,
        file_bytes: Vec<u8>,
        packet_parser: PacketParser,
    ) -> Result<Self, DataLinkError> {
        let source = source_with_optional_gzip(Cursor::new(file_bytes))?;
        Self::from_source(filename, source, packet_parser)
    }

    fn from_source(
        filename: &str,
        mut source: Box<dyn Read>,
        packet_parser: PacketParser,
    ) -> Result<Self, DataLinkError> {
        let mut format_magic = [0; 4];
        let format_magic_len = read_prefix(source.as_mut(), &mut format_magic)?;
        let is_pcapng =
            format_magic_len == format_magic.len() && format_magic == [0x0a, 0x0d, 0x0d, 0x0a];
        let source: Box<dyn Read> =
            Box::new(Cursor::new(format_magic[..format_magic_len].to_vec()).chain(source));

        let reader = if is_pcapng {
            ReaderKind::PcapNg {
                reader: PcapNgReader::new(source)?,
                interfaces: Vec::new(),
            }
        } else {
            let reader = PcapReader::new(source)?;
            let link_type = reader.header().datalink;
            ReaderKind::Pcap { reader, link_type }
        };

        Ok(Self {
            filename: filename.to_string(),
            packet_parser,
            reader,
        })
    }

    /// Read the next raw packet record, preserving its capture metadata.
    pub fn next_capture_packet(&mut self) -> Result<Option<CapturePacket>, DataLinkError> {
        with_next_capture_packet(
            &self.filename,
            &mut self.reader,
            |link_type, original_len, data| {
                Ok(CapturePacket {
                    link_type,
                    original_len,
                    data: data.to_vec(),
                })
            },
        )
    }
}

fn with_next_capture_packet<T, F>(
    filename: &str,
    reader: &mut ReaderKind,
    mut process: F,
) -> Result<Option<T>, DataLinkError>
where
    F: FnMut(DataLink, u32, &[u8]) -> Result<T, DataLinkError>,
{
    match reader {
        ReaderKind::Pcap { reader, link_type } => match reader.next_packet() {
            Some(Ok(packet)) => {
                process(*link_type, packet.orig_len, packet.data.as_ref()).map(Some)
            }
            Some(Err(error)) => Err(error.into()),
            None => Ok(None),
        },
        ReaderKind::PcapNg { reader, interfaces } => loop {
            let block = match reader.next_block() {
                Some(Ok(block)) => block,
                Some(Err(error)) => return Err(error.into()),
                None => return Ok(None),
            };

            match block {
                Block::EnhancedPacket(packet) => {
                    let link_type =
                        pcapng_link_type(interfaces, packet.interface_id as usize, filename)?;
                    return process(link_type, packet.original_len, packet.data.as_ref()).map(Some);
                }
                Block::Packet(packet) => {
                    let link_type =
                        pcapng_link_type(interfaces, packet.interface_id as usize, filename)?;
                    return process(link_type, packet.original_len, packet.data.as_ref()).map(Some);
                }
                Block::SimplePacket(packet) => {
                    let interface = interfaces.first().copied().ok_or_else(|| {
                        DataLinkError::PcapError(format!(
                            "simple packet in {} has no interface description",
                            filename
                        ))
                    })?;
                    let original_len = packet.original_len;
                    let captured_len = captured_len(original_len, interface.snaplen, filename)?;
                    let data = packet.data.as_ref();
                    if data.len() < captured_len {
                        return Err(DataLinkError::PcapError(format!(
                            "simple packet in {} is shorter than its captured length {}",
                            filename, captured_len
                        )));
                    }
                    return process(interface.link_type, original_len, &data[..captured_len])
                        .map(Some);
                }
                Block::SectionHeader(_) => interfaces.clear(),
                Block::InterfaceDescription(interface) => interfaces.push(PcapNgInterface {
                    link_type: interface.linktype,
                    snaplen: interface.snaplen,
                }),
                Block::NameResolution(_)
                | Block::InterfaceStatistics(_)
                | Block::SystemdJournalExport(_)
                | Block::Unknown(_) => {}
            }
        },
    }
}

fn pcapng_link_type(
    interfaces: &[PcapNgInterface],
    interface_id: usize,
    filename: &str,
) -> Result<DataLink, DataLinkError> {
    interfaces
        .get(interface_id)
        .map(|interface| interface.link_type)
        .ok_or_else(|| {
            DataLinkError::PcapError(format!(
                "packet in {} references missing interface {}",
                filename, interface_id
            ))
        })
}

fn captured_len(original_len: u32, snaplen: u32, filename: &str) -> Result<usize, DataLinkError> {
    let captured_len = if snaplen == 0 {
        original_len
    } else {
        snaplen.min(original_len)
    };
    captured_len.try_into().map_err(|_| {
        DataLinkError::PcapError(format!(
            "simple packet in {} has an unsupported captured length {}",
            filename, captured_len
        ))
    })
}

impl PacketRead for PcapFileReader {
    fn read(&mut self) -> Result<Packet, DataLinkError> {
        let filename = self.filename.as_str();
        let packet_parser = &self.packet_parser;
        let packet = with_next_capture_packet(filename, &mut self.reader, |link_type, _, data| {
            parse_packet(packet_parser, link_type, data)
        })?;
        packet.ok_or(DataLinkError::Eof)
    }
}

fn parse_packet(
    packet_parser: &PacketParser,
    link_type: DataLink,
    data: &[u8],
) -> Result<Packet, DataLinkError> {
    let (_rest, packet) = match link_type {
        DataLink::ETHERNET => packet_parser.parse_packet::<Ether>(data)?,
        _ => packet_parser.parse_packet::<Raw>(data)?,
    };
    // TODO: log warning of un-read data?
    Ok(packet)
}

fn source_with_optional_gzip<R>(mut source: R) -> Result<Box<dyn Read>, DataLinkError>
where
    R: Read + 'static,
{
    let mut compression_magic = [0; 2];
    let compression_magic_len = read_prefix(&mut source, &mut compression_magic)?;
    let source: Box<dyn Read> =
        Box::new(Cursor::new(compression_magic[..compression_magic_len].to_vec()).chain(source));

    if compression_magic_len == compression_magic.len() && compression_magic == [0x1f, 0x8b] {
        Ok(Box::new(GzDecoder::new(source)))
    } else {
        Ok(source)
    }
}

fn read_prefix<R: Read + ?Sized>(
    reader: &mut R,
    prefix: &mut [u8],
) -> Result<usize, DataLinkError> {
    let mut length = 0;
    while length < prefix.len() {
        let read = reader.read(&mut prefix[length..])?;
        if read == 0 {
            break;
        }
        length += read;
    }
    Ok(length)
}

impl PacketWrite for PcapFileWriter {
    fn write(&mut self, packet: Packet) -> Result<(), DataLinkError> {
        let data = packet.to_bytes()?;
        let data_len = u32::try_from(data.len()).map_err(|_e| {
            DataLinkError::PcapError(format!(
                "failed to convert packet length {} > {}",
                data.len(),
                u32::MAX
            ))
        })?;

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| {
                DataLinkError::PcapError(format!("system clock is before Unix epoch: {error}"))
            })?;
        let pcap_packet = PcapPacket::new(timestamp, data_len, &data);

        match self.writer.write_packet(&pcap_packet) {
            Ok(_) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pcap_file::pcapng::{
        blocks::{
            enhanced_packet::EnhancedPacketBlock, interface_description::InterfaceDescriptionBlock,
            packet::PacketBlock, simple_packet::SimplePacketBlock,
        },
        PcapNgWriter,
    };
    use std::{borrow::Cow, time::Duration};

    #[test]
    fn reads_all_pcapng_packet_block_types() {
        let data = vec![0u8; 14];
        let mut writer = PcapNgWriter::new(Vec::new()).unwrap();
        writer
            .write_pcapng_block(InterfaceDescriptionBlock::new(DataLink::ETHERNET, 65_535))
            .unwrap();
        writer
            .write_pcapng_block(EnhancedPacketBlock {
                interface_id: 0,
                timestamp: Duration::ZERO,
                original_len: data.len() as u32,
                data: Cow::Owned(data.clone()),
                options: vec![],
            })
            .unwrap();
        writer
            .write_pcapng_block(PacketBlock {
                interface_id: 0,
                drop_count: 0,
                timestamp: 0,
                captured_len: data.len() as u32,
                original_len: data.len() as u32,
                data: Cow::Owned(data.clone()),
                options: vec![],
            })
            .unwrap();
        writer
            .write_pcapng_block(SimplePacketBlock {
                original_len: data.len() as u32,
                data: Cow::Owned(data.clone()),
            })
            .unwrap();

        let mut reader =
            PcapFileReader::from_bytes("test.pcapng", writer.into_inner(), PacketParser::new())
                .unwrap();
        let mut packets = Vec::new();
        while let Some(packet) = reader.next_capture_packet().unwrap() {
            packets.push(packet);
        }

        assert_eq!(packets.len(), 3);
        assert!(packets
            .iter()
            .all(|packet| packet.link_type == DataLink::ETHERNET));
        assert!(packets
            .iter()
            .all(|packet| packet.original_len == data.len() as u32));
        assert!(packets.iter().all(|packet| packet.data == data));
    }
}
