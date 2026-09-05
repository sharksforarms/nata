/*!
(Doc only) Default layer bindings

Documentation only module, listing the default layer bindings for [PacketParser](crate::packet::PacketParser).

# Layer Bindings

| Layer | Condition | Next Layer
|-----------|------------------|------------
| [Ether] | type == Ipv4 | [Ipv4]
| [Ether] | type == Ipv6 | [Ipv6]
| [Ipv4] | protocol == Tcp | [Tcp]
| [Ipv4] | protocol == Udp | [Udp]
| [Ipv4] | protocol == Icmp | [Icmp4]
| [Ipv6] | protocol == Tcp | [Tcp]
| [Ipv6] | protocol == Udp | [Udp]

[Ether]: crate::layer::ether::Ether
[Ipv4]: crate::layer::ip::Ipv4
[Ipv6]: crate::layer::ip::Ipv6
[Udp]: crate::layer::udp::Udp
[Tcp]: crate::layer::tcp::Tcp
[Icmp4]: crate::layer::icmp::Icmp4
*/
use crate::{
    layer::{
        ether::{Ether, EtherType},
        icmp::Icmp4,
        ip::{IpProtocol, Ipv4, Ipv6},
        raw::Raw,
        tcp::Tcp,
        udp::Udp,
        PacketLayer,
    },
    packet::PacketParser,
};

/// Create a [PacketParser](crate::packet::PacketParser) with a set of bindings using layers
/// defined in the crate
pub(crate) fn create_packetparser() -> PacketParser {
    let mut pb = PacketParser::without_bindings();

    pb.bind_layer(|ether: &Ether, _rest| match ether.ether_type {
        EtherType::IPv4 => Some(Ipv4::parse_layer),
        EtherType::IPv6 => Some(Ipv6::parse_layer),
        _ => Some(Raw::parse_layer),
    });

    pb.bind_layer(|ipv4: &Ipv4, _rest| match ipv4.protocol {
        IpProtocol::TCP => Some(Tcp::parse_layer),
        IpProtocol::UDP => Some(Udp::parse_layer),
        IpProtocol::ICMP => Some(Icmp4::parse_layer),
        _ => Some(Raw::parse_layer),
    });

    pb.bind_layer(|ipv6: &Ipv6, _rest| match ipv6.next_header {
        IpProtocol::TCP => Some(Tcp::parse_layer),
        IpProtocol::UDP => Some(Udp::parse_layer),
        _ => Some(Raw::parse_layer),
    });

    pb.bind_layer(|_tcp: &Tcp, _rest| Some(Raw::parse_layer));
    pb.bind_layer(|_udp: &Udp, _rest| Some(Raw::parse_layer));

    pb
}
