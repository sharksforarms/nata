use nata::{
    datalink::{pcapfile::PcapFile, InterfaceReader},
    is_layer,
    layer::{ether::Ether, raw::Raw},
    packet::Packet,
};

macro_rules! gen_pcap_rw_test {
    ($name:ident, $count:expr, $body:expr) => {
        #[test]
        #[cfg_attr(miri, ignore)]
        fn $name() {
            let interface = InterfaceReader::init::<PcapFile>(concat!(
                "./tests/pcaps/",
                stringify!($name),
                ".pcap"
            ))
            .unwrap();

            let mut count = 0;
            for pkt in interface {
                $body(&pkt);

                let bytes1 = pkt.to_bytes().unwrap();
                let mut pkt2 = pkt.clone();
                pkt2.finalize().unwrap();
                let bytes2 = pkt.to_bytes().unwrap();

                assert_eq!(bytes1, bytes2);
                count += 1;
            }

            assert_eq!($count, count);
        }
    };
}

gen_pcap_rw_test!(test_pcap_read_write, 14, |pkt: &Packet| {
    let first_layer = pkt.layers().first().unwrap();
    assert!(is_layer!(first_layer, Ether));
});

gen_pcap_rw_test!(test_pcap_unhandled_read_write, 1, |pkt: &Packet| {
    // since these are not handled in nata, there should only be a single Raw layer per packet
    assert_eq!(1, pkt.layers().len());

    let first_layer = pkt.layers().first().unwrap();
    assert!(is_layer!(first_layer, Raw));
});
