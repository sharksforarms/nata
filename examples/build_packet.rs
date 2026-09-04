use nata::prelude::*;
use std::net::Ipv4Addr;

fn main() {
    let src_mac = MacAddress::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    let dst_mac = MacAddress::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x02]);
    let src_ip = Ipv4Addr::new(192, 0, 2, 1);
    let dst_ip = Ipv4Addr::new(198, 51, 100, 2);

    let mut packet = Packet::builder()
        .layer(Ether::new(src_mac, dst_mac))
        .layer(Ipv4::new(src_ip, dst_ip).protocol(IpProtocol::UDP))
        .layer(Udp::new(40_000, 53))
        .payload(b"hello from nata")
        .build()
        .unwrap();

    let bytes = packet.bytes().unwrap();
    let parsed = parse(&bytes).unwrap();

    assert_eq!(parsed.as_ref().len(), 4);
    assert_eq!("Ether / Ipv4 / Udp / Raw", parsed.summary());
}
