#![cfg(feature = "std")]

use flate2::{write::GzEncoder, Compression};
use nata::{
    datalink::{pcapfile::PcapFile, InterfaceReader},
    is_layer,
    layer::{ether::Ether, raw::Raw},
    packet::Packet,
};
use pcap_file::{
    pcapng::{
        blocks::{
            enhanced_packet::EnhancedPacketBlock, interface_description::InterfaceDescriptionBlock,
            packet::PacketBlock, simple_packet::SimplePacketBlock,
        },
        PcapNgWriter,
    },
    DataLink,
};
use std::{
    borrow::Cow,
    env, fs,
    io::Write,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
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

#[test]
fn test_pcapng_public_interface_reads_packet_blocks() {
    let path = temporary_capture_path("pcapng");
    fs::write(&path, pcapng_bytes()).unwrap();

    let packets = read_raw_packets(&path);
    fs::remove_file(path).unwrap();

    assert_eq!(packets, vec![vec![1, 2, 3], vec![4, 5], vec![6, 7, 8]]);
}

#[test]
fn test_gzip_pcapng_public_interface_reads_packet_blocks() {
    let path = temporary_capture_path("pcapng.gz");
    let file = fs::File::create(&path).unwrap();
    let mut encoder = GzEncoder::new(file, Compression::default());
    encoder.write_all(&pcapng_bytes()).unwrap();
    encoder.finish().unwrap();

    let packets = read_raw_packets(&path);
    fs::remove_file(path).unwrap();

    assert_eq!(packets, vec![vec![1, 2, 3], vec![4, 5], vec![6, 7, 8]]);
}

fn read_raw_packets(path: &Path) -> Vec<Vec<u8>> {
    let interface = InterfaceReader::init::<PcapFile>(path.to_str().unwrap()).unwrap();
    interface.map(|packet| packet.to_bytes().unwrap()).collect()
}

fn pcapng_bytes() -> Vec<u8> {
    let mut writer = PcapNgWriter::new(Vec::new()).unwrap();
    writer
        .write_pcapng_block(InterfaceDescriptionBlock::new(DataLink::RAW, 3))
        .unwrap();
    writer
        .write_pcapng_block(EnhancedPacketBlock {
            interface_id: 0,
            timestamp: std::time::Duration::ZERO,
            original_len: 4,
            data: Cow::Owned(vec![1, 2, 3]),
            options: vec![],
        })
        .unwrap();
    writer
        .write_pcapng_block(PacketBlock {
            interface_id: 0,
            drop_count: 0,
            timestamp: 0,
            captured_len: 2,
            original_len: 4,
            data: Cow::Owned(vec![4, 5]),
            options: vec![],
        })
        .unwrap();
    writer
        .write_pcapng_block(SimplePacketBlock {
            original_len: 4,
            data: Cow::Owned(vec![6, 7, 8, 9]),
        })
        .unwrap();
    writer.into_inner()
}

fn temporary_capture_path(extension: &str) -> PathBuf {
    static NEXT_ID: AtomicU64 = AtomicU64::new(0);
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    env::temp_dir().join(format!(
        "nata-pcap-test-{}-{id}.{extension}",
        std::process::id()
    ))
}
