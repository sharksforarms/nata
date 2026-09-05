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
    },
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
        let mut file = File::open(filename)?;
        let mut compression_magic = [0; 2];
        let compression_magic_len = read_prefix(&mut file, &mut compression_magic)?;
        drop(file);

        let is_gzip =
            compression_magic_len == compression_magic.len() && compression_magic == [0x1f, 0x8b];
        let source: Box<dyn Read> = if is_gzip {
            Box::new(GzDecoder::new(File::open(filename)?))
        } else {
            Box::new(File::open(filename)?)
        };

        Self::from_source(filename, source, packet_parser)
    }

    #[cfg(test)]
    fn from_bytes(
        filename: &str,
        file_bytes: Vec<u8>,
        packet_parser: PacketParser,
    ) -> Result<Self, DataLinkError> {
        let source: Box<dyn Read> = if file_bytes.starts_with(&[0x1f, 0x8b]) {
            Box::new(GzDecoder::new(Cursor::new(file_bytes)))
        } else {
            Box::new(Cursor::new(file_bytes))
        };
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
        let filename = self.filename.clone();
        match &mut self.reader {
            ReaderKind::Pcap { reader, link_type } => match reader.next_packet() {
                Some(Ok(packet)) => Ok(Some(CapturePacket {
                    link_type: *link_type,
                    original_len: packet.orig_len,
                    data: packet.data.into_owned(),
                })),
                Some(Err(error)) => Err(error.into()),
                None => Ok(None),
            },
            ReaderKind::PcapNg { reader } => loop {
                let block = match reader.next_block() {
                    Some(Ok(block)) => block,
                    Some(Err(error)) => return Err(error.into()),
                    None => return Ok(None),
                };

                match block {
                    Block::EnhancedPacket(packet) => {
                        let interface_id = packet.interface_id;
                        let original_len = packet.original_len;
                        let data = packet.data.into_owned();
                        let link_type = reader
                            .interfaces()
                            .get(interface_id as usize)
                            .map(|interface| interface.linktype)
                            .ok_or_else(|| {
                                DataLinkError::PcapError(format!(
                                    "packet in {} references missing interface {}",
                                    filename, interface_id
                                ))
                            })?;
                        return Ok(Some(CapturePacket {
                            link_type,
                            original_len,
                            data,
                        }));
                    }
                    Block::Packet(packet) => {
                        let interface_id = packet.interface_id;
                        let original_len = packet.original_len;
                        let data = packet.data.into_owned();
                        let link_type = reader
                            .interfaces()
                            .get(interface_id as usize)
                            .map(|interface| interface.linktype)
                            .ok_or_else(|| {
                                DataLinkError::PcapError(format!(
                                    "packet in {} references missing interface {}",
                                    filename, interface_id
                                ))
                            })?;
                        return Ok(Some(CapturePacket {
                            link_type,
                            original_len,
                            data,
                        }));
                    }
                    Block::SimplePacket(packet) => {
                        let original_len = packet.original_len;
                        let mut data = packet.data.into_owned();
                        let interface = reader.interfaces().first().ok_or_else(|| {
                            DataLinkError::PcapError(format!(
                                "simple packet in {} has no interface description",
                                filename
                            ))
                        })?;
                        let link_type = interface.linktype;
                        let snaplen = interface.snaplen;
                        let captured_len = if snaplen == 0 {
                            original_len
                        } else {
                            snaplen.min(original_len)
                        };
                        let captured_len: usize = captured_len.try_into().map_err(|_| {
                            DataLinkError::PcapError(format!(
                                "simple packet in {} has an unsupported captured length {}",
                                filename, captured_len
                            ))
                        })?;
                        if data.len() < captured_len {
                            return Err(DataLinkError::PcapError(format!(
                                "simple packet in {} is shorter than its captured length {}",
                                filename, captured_len
                            )));
                        }
                        data.truncate(captured_len);
                        return Ok(Some(CapturePacket {
                            link_type,
                            original_len,
                            data,
                        }));
                    }
                    Block::SectionHeader(_) | Block::InterfaceDescription(_) => {}
                    Block::NameResolution(_)
                    | Block::InterfaceStatistics(_)
                    | Block::SystemdJournalExport(_)
                    | Block::Unknown(_) => {}
                }
            },
        }
    }
}

impl PacketRead for PcapFileReader {
    fn read(&mut self) -> Result<Packet, DataLinkError> {
        let capture_packet = self.next_capture_packet()?.ok_or(DataLinkError::Eof)?;
        let (_rest, packet) = match capture_packet.link_type {
            DataLink::ETHERNET => self
                .packet_parser
                .parse_packet::<Ether>(&capture_packet.data)?,
            _ => self
                .packet_parser
                .parse_packet::<Raw>(&capture_packet.data)?,
        };
        // TODO: log warning of un-read data?
        Ok(packet)
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
