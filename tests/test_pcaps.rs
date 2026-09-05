#![cfg(feature = "std")]

use nata::{
    datalink::{pcapfile::PcapFile, InterfaceReader, PacketReadExt},
    layer::{ether::Ether, raw::Raw},
    packet::Packet,
};

macro_rules! gen_pcap_rw_test {
    ($name:ident, $count:expr, $body:expr) => {
        #[test]
        #[cfg_attr(miri, ignore)]
        fn $name() {
            let mut interface = InterfaceReader::init::<PcapFile>(concat!(
                "./tests/pcaps/",
                stringify!($name),
                ".pcap"
            ))
            .unwrap();

            let mut count = 0;
            for pkt in interface.try_iter() {
                let pkt = pkt.unwrap();
                $body(&pkt);

                let bytes1 = pkt.clone().into_bytes().unwrap();
                let bytes2 = pkt.into_bytes().unwrap();

                assert_eq!(bytes1, bytes2);
                count += 1;
            }

            assert_eq!($count, count);
        }
    };
}

gen_pcap_rw_test!(test_pcap_read_write, 14, |pkt: &Packet| {
    let first_layer = pkt.as_ref().iter().next().unwrap();
    assert!(first_layer.as_any().is::<Ether>());
});

gen_pcap_rw_test!(test_pcap_unhandled_read_write, 1, |pkt: &Packet| {
    // since these are not handled in nata, there should only be a single Raw layer per packet
    assert_eq!(1, pkt.as_ref().len());
    let first_layer = pkt.as_ref().iter().next().unwrap();
    assert!(first_layer.as_any().is::<Raw>());
});
