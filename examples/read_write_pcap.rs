//! Read packets from one PCAP file and write them to another.
//!
//! This exercises Hatchet's complete offline I/O path: each captured frame is
//! decoded into typed layers, serialized again, and stored in a new PCAP file.

use hatchet::datalink::{pcapfile::PcapFile, InterfaceReader, InterfaceWriter, PacketWrite};
use std::{env, fs, process};

fn usage(program: &str) -> ! {
    eprintln!("usage: {program} <input.pcap> <output.pcap>");
    process::exit(2);
}

fn main() {
    let mut args = env::args();
    let program = args.next().unwrap_or_else(|| "read_write_pcap".into());
    let input = args.next().unwrap_or_else(|| usage(&program));
    let output = args.next().unwrap_or_else(|| usage(&program));
    if args.next().is_some() {
        usage(&program);
    }

    let input_path = fs::canonicalize(&input).expect("failed to resolve input PCAP path");
    if fs::canonicalize(&output).is_ok_and(|output_path| output_path == input_path) {
        eprintln!("input and output PCAP files must be different");
        process::exit(2);
    }

    let mut reader = InterfaceReader::init::<PcapFile>(&input).expect("failed to open input PCAP");
    let mut writer =
        InterfaceWriter::init::<PcapFile>(&output).expect("failed to create output PCAP");
    let mut packet_count = 0;

    for packet in &mut reader {
        packet_count += 1;
        println!("Packet {packet_count}: {packet:?}");
        writer.write(packet).expect("failed to write packet");
    }

    println!("Wrote {packet_count} packets to {output}");
}
