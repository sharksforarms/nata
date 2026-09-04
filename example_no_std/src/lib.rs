#![no_std]

use core::net::Ipv4Addr;
use nata::prelude::*;

pub const PAYLOAD: &[u8] = b"nata/no_std";

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
    let packet = parse(frame).ok()?;
    let ipv4 = packet.get::<Ipv4>()?;
    let udp = packet.get::<Udp>()?;
    let raw = packet.get::<Raw>()?;

    Some(UdpSummary {
        source_address: ipv4.src,
        destination_address: ipv4.dst,
        source_port: udp.sport,
        destination_port: udp.dport,
        payload_length: raw.data.len(),
    })
}

/// Construct and inspect a packet using only Nata's `no_std` APIs.
pub fn build_and_inspect_udp() -> Option<UdpSummary> {
    let mut packet = Packet::builder()
        .layer(Ether::new(
            MacAddress::new([0x02, 0, 0, 0, 0, 1]),
            MacAddress::new([0x02, 0, 0, 0, 0, 2]),
        ))
        .layer(
            Ipv4::new(Ipv4Addr::new(192, 0, 2, 1), Ipv4Addr::new(198, 51, 100, 2))
                .protocol(IpProtocol::UDP),
        )
        .layer(Udp::new(40_000, 53))
        .payload(PAYLOAD)
        .build()
        .ok()?;

    inspect_udp_frame(&packet.bytes().ok()?)
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
