/*!
Packet interface implementation using `libpcap`

libpcap interface exposed via libpnet
*/
use pnet::datalink::{self, Channel, DataLinkReceiver, DataLinkSender, NetworkInterface};

use super::{BackendInterface, DataLinkError, PacketInterface, PacketRead, PacketWrite};
use crate::{
    datalink::InterfaceMetadata,
    layer::ether::{Ether, MacAddress},
    packet::{Packet, PacketParser},
};

/// LibPcap network interface
pub struct Pcap;

/// LibPcap reader
pub struct PcapReader {
    packet_parser: PacketParser,
    reader: Box<dyn DataLinkReceiver + 'static>,
}

/// LibPcap writer
pub struct PcapWriter {
    writer: Box<dyn DataLinkSender + 'static>,
}

impl PacketInterface for Pcap {
    type Reader = PcapReader;
    type Writer = PcapWriter;

    fn init(
        interface_name: &str,
    ) -> Result<BackendInterface<Self::Reader, Self::Writer>, DataLinkError> {
        <Self as PacketInterface>::init_with_parser(interface_name, PacketParser::new())
    }

    fn init_with_parser(
        interface_name: &str,
        packet_parser: crate::packet::PacketParser,
    ) -> Result<BackendInterface<Self::Reader, Self::Writer>, DataLinkError>
    where
        Self: Sized,
    {
        let interface_names_match = |iface: &NetworkInterface| iface.name == interface_name;

        // Find the network interface with the provided name
        let interfaces = datalink::interfaces();
        let interface = interfaces
            .into_iter()
            .find(interface_names_match)
            .ok_or(DataLinkError::InterfaceNotFound)?;

        let (tx, rx) = match datalink::channel(&interface, Default::default()) {
            Ok(Channel::Ethernet(tx, rx)) => Ok((tx, rx)),
            Ok(_) => Err(DataLinkError::UnhandledInterfaceType),
            Err(e) => Err(DataLinkError::IoError(e)),
        }?;

        Ok(BackendInterface {
            reader: PcapReader {
                packet_parser,
                reader: rx,
            },
            writer: PcapWriter { writer: tx },
            metadata: InterfaceMetadata {
                mac_address: interface.mac.map(|v| MacAddress(v.octets())),
            },
        })
    }
}

impl PacketRead for PcapReader {
    fn read(&mut self) -> Result<Packet, DataLinkError> {
        match self.reader.next() {
            Ok(packet_bytes) => {
                let (_rest, packet) = self.packet_parser.parse_partial::<Ether>(packet_bytes)?;
                // TODO: log warning of un-read data?
                Ok(packet)
            }
            Err(e) => Err(DataLinkError::IoError(e)),
        }
    }
}

impl PacketWrite for PcapWriter {
    fn write(&mut self, mut packet: Packet) -> Result<(), DataLinkError> {
        let bytes = packet.bytes()?;
        if let Some(res) = self.writer.send_to(bytes.as_ref(), None) {
            Ok(res?)
        } else {
            Err(DataLinkError::BufferError)
        }
    }
}
