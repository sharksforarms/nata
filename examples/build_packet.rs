use hatchet::{
    is_layer,
    layer::{
        ether::{Ether, EtherType, MacAddress},
        ip::{IpProtocol, Ipv4},
        raw::Raw,
        udp::Udp,
        LayerOwned,
    },
    packet::{Packet, PacketParser},
};

fn main() {
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
            data: b"hello from hatchet".to_vec(),
            ..Raw::default()
        }),
    ];

    let mut packet = Packet::from_layers(layers);
    packet.finalize().unwrap();

    let bytes = packet.to_bytes().unwrap();
    let (rest, parsed) = PacketParser::new().parse_packet::<Ether>(&bytes).unwrap();

    assert!(rest.is_empty());
    assert_eq!(parsed.layers().len(), 4);
    assert!(is_layer!(parsed.layers()[0], Ether));
    assert!(is_layer!(parsed.layers()[1], Ipv4));
    assert!(is_layer!(parsed.layers()[2], Udp));
    assert!(is_layer!(parsed.layers()[3], Raw));
}
