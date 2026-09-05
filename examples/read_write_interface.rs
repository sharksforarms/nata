use nata::{datalink::Interface, prelude::*};

fn main() {
    // Read from interface
    let mut interface = Interface::open("lo").unwrap();

    let (mut rx, mut tx) = interface.split();

    for pkt in rx.try_iter() {
        let pkt = pkt.unwrap();
        println!("Packet: {pkt:?}");

        // send a hello world for every packet
        let p = Packet::builder()
            .layer(Ether::default())
            .layer(Ipv4::default())
            .layer(Tcp::default())
            .payload(b"hello world")
            .build()
            .unwrap();
        tx.send(p).unwrap();
    }
}
