use nata::{
    datalink::{pcap::Pcap, Interface, PacketWrite},
    layer::{ether::Ether, ip::Ipv4, raw::Raw, tcp::Tcp, LayerExt, LayerOwned},
    packet::Packet,
};

fn main() {
    // Read from interface
    let int = Interface::init::<Pcap>("lo").unwrap();

    let (mut rx, mut tx) = int.into_split();
    //let (mut rx, mut tx) = int.split();

    for pkt in &mut rx {
        println!("Packet: {:?}", pkt);

        // send a hello world for every packet
        let layers: Vec<LayerOwned> = vec![
            Box::new(Ether::default()),
            Box::new(Ipv4::default()),
            Box::new(Tcp::default()),
            Box::new(Raw::parse(b"hello world").unwrap().1),
        ];
        let mut p = Packet::from_layers(layers);
        p.finalize().unwrap();
        tx.write(p).unwrap();
    }
}
