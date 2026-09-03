#![no_std]

extern crate alloc;

use alloc::{boxed::Box, vec, vec::Vec};
use hatchet::{
    get_layer,
    layer::{
        ether::{Ether, EtherType, MacAddress},
        ip::{IpProtocol, Ipv4},
        raw::Raw,
        udp::Udp,
        LayerOwned,
    },
    packet::{Packet, PacketParser},
};

pub const PAYLOAD: &[u8] = b"hatchet/no_std";

/// The fields an embedded application might extract from a UDP frame.
#[derive(Debug, PartialEq, Eq)]
pub struct UdpSummary {
    pub source_address: u32,
    pub destination_address: u32,
    pub source_port: u16,
    pub destination_port: u16,
    pub payload_length: usize,
}

/// Parse an Ethernet/IPv4/UDP frame and return the fields relevant to an
/// embedded application.
pub fn inspect_udp_frame(frame: &[u8]) -> Option<UdpSummary> {
    let (rest, packet) = PacketParser::new().parse_packet::<Ether>(frame).ok()?;
    if !rest.is_empty() {
        return None;
    }

    let ipv4 = packet
        .layers()
        .iter()
        .find_map(|layer| get_layer!(layer, Ipv4))?;
    let udp = packet
        .layers()
        .iter()
        .find_map(|layer| get_layer!(layer, Udp))?;
    let raw = packet
        .layers()
        .iter()
        .find_map(|layer| get_layer!(layer, Raw))?;

    Some(UdpSummary {
        source_address: ipv4.src,
        destination_address: ipv4.dst,
        source_port: udp.sport,
        destination_port: udp.dport,
        payload_length: raw.data.len(),
    })
}

/// Construct and inspect a packet using only Hatchet's `no_std` APIs.
pub fn build_and_inspect_udp() -> Option<UdpSummary> {
    let layers: Vec<LayerOwned> = vec![
        Box::new(Ether {
            dst: MacAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x02]),
            src: MacAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]),
            ether_type: EtherType::IPv4,
        }),
        Box::new(Ipv4 {
            src: 0xc000_0201, // 192.0.2.1
            dst: 0xc633_6402, // 198.51.100.2
            ttl: 64,
            protocol: IpProtocol::UDP,
            ..Ipv4::default()
        }),
        Box::new(Udp {
            sport: 40_000,
            dport: 53,
            ..Udp::default()
        }),
        Box::new(Raw {
            data: PAYLOAD.to_vec(),
            ..Raw::default()
        }),
    ];

    let mut packet = Packet::from_layers(layers);
    packet.finalize().ok()?;
    inspect_udp_frame(&packet.to_bytes().ok()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_round_trip() {
        assert_eq!(
            Some(UdpSummary {
                source_address: 0xc000_0201,
                destination_address: 0xc633_6402,
                source_port: 40_000,
                destination_port: 53,
                payload_length: PAYLOAD.len(),
            }),
            build_and_inspect_udp()
        );
    }
}
