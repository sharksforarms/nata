use hexlit::hex;
use nata::{datalink::Interface, prelude::*};
use std::env;
use std::net::Ipv4Addr;
use std::str::FromStr;

fn main() {
    let args: Vec<String> = env::args().collect();
    let interface = args.get(1).expect("expected a network interface");
    let ip_addr = args.get(2).expect("expected an ipv4 address as argument");

    // Initiate a read/write channel on the network interface using the configured backend
    let mut int = Interface::open(interface).unwrap();
    let mac_addr = int.mac_address().cloned().unwrap();
    println!("mac_addr: {:x?}", mac_addr);
    let (mut rx, mut tx) = int.split();

    // Create a ICMP Echo Request packet
    let echo_request = Packet::builder()
        .layer(Ether {
            dst: MacAddress(hex!("ec086b507d58")), // Gateway mac
            src: mac_addr,
            ether_type: EtherType::IPv4,
        })
        .layer(Ipv4 {
            src: Ipv4Addr::from_str("192.168.1.106").unwrap().into(), // Src Ip
            dst: Ipv4Addr::from_str(ip_addr).unwrap().into(),
            ttl: 124,
            protocol: IpProtocol::ICMP,
            identification: 0x3716,
            flags: 0b0100,
            ..Default::default()
        })
        .layer(Icmp4 {
            icmp_type: IcmpType::EchoRequest,
            data: vec![0xFF, 0xFF],
            message: 0xDFADBEFF,
            ..Default::default()
        })
        .build()
        .unwrap();

    tx.send(echo_request).unwrap();
    for pkt in rx.try_iter() {
        let pkt = pkt.unwrap();
        if pkt.has::<Icmp4>() {
            println!("Packet: {:?}", pkt);
        }
    }
}
