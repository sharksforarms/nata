/*!
Packet interface implementation using `libpnet`
*/
use pnet::datalink::{self, Channel, DataLinkReceiver, DataLinkSender, NetworkInterface};

use super::{BackendInterface, DataLinkError, PacketInterface, PacketRead, PacketWrite};
use crate::{
    datalink::InterfaceMetadata,
    layer::ether::{Ether, MacAddress},
    packet::{Packet, PacketParser},
};
use alloc::boxed::Box;

/// Pnet network interface
pub struct Pnet;

/// Pnet reader
pub struct PnetReader {
    packet_parser: PacketParser,
    reader: Box<dyn DataLinkReceiver + 'static>,
}

/// Pnet writer
pub struct PnetWriter {
    writer: Box<dyn DataLinkSender + 'static>,
}

impl PacketInterface for Pnet {
    type Reader = PnetReader;
    type Writer = PnetWriter;

    fn init(
        interface_name: &str,
    ) -> Result<BackendInterface<Self::Reader, Self::Writer>, DataLinkError> {
        Self::init_with_parser(interface_name, PacketParser::new())
    }

    fn init_with_parser(
        interface_name: &str,
        packet_parser: PacketParser,
    ) -> Result<BackendInterface<Self::Reader, Self::Writer>, DataLinkError> {
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
            reader: PnetReader {
                packet_parser,
                reader: rx,
            },
            writer: PnetWriter { writer: tx },
            metadata: InterfaceMetadata {
                mac_address: interface.mac.map(|v| MacAddress(v.octets())),
            },
        })
    }
}

impl PacketRead for PnetReader {
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

impl PacketWrite for PnetWriter {
    fn write(&mut self, mut packet: Packet) -> Result<(), DataLinkError> {
        let bytes = packet.bytes()?;
        if let Some(res) = self.writer.send_to(bytes.as_ref(), None) {
            Ok(res?)
        } else {
            Err(DataLinkError::BufferError)
        }
    }
}
