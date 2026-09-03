/*!
    Based on https://github.com/rustwasm/wasm-pack-template
*/
use std::fmt::Write as _;

use nata::{
    layer::{ether::Ether, raw::Raw},
    packet::{Packet, PacketError, PacketParser},
};
use pcap_file::{pcap::PcapParser, DataLink};
use wasm_bindgen::prelude::*;

pub fn set_panic_hook() {
    // When the `console_error_panic_hook` feature is enabled, we can call the
    // `set_panic_hook` function at least once during initialization, and then
    // we will get better error messages if our code ever panics.
    //
    // For more details see
    // https://github.com/rustwasm/console_error_panic_hook#readme
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}

// When the `wee_alloc` feature is enabled, use `wee_alloc` as the global
// allocator.
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

fn parse_packet<'a>(
    parser: &PacketParser,
    datalink: DataLink,
    input: &'a [u8],
) -> Result<(&'a [u8], Packet), PacketError> {
    if datalink == DataLink::ETHERNET {
        parser.parse_packet::<Ether>(input)
    } else {
        parser.parse_packet::<Raw>(input)
    }
}

/// Parse a complete legacy PCAP file and return one pretty `Debug` dump per packet.
#[wasm_bindgen]
pub fn read_packets(input: &[u8]) -> Result<String, JsValue> {
    set_panic_hook();
    read_packets_debug(input).map_err(|error| JsValue::from_str(&error))
}

fn read_packets_debug(input: &[u8]) -> Result<String, String> {
    let (mut remaining, pcap_parser) =
        PcapParser::new(input).map_err(|error| format!("Invalid PCAP header: {error}"))?;
    let header = pcap_parser.header();
    let packet_parser = PacketParser::new();
    let mut output = String::new();
    let mut packet_count = 0;

    writeln!(&mut output, "PCAP header:\n{header:#?}\n").expect("writing to a String cannot fail");

    while !remaining.is_empty() {
        let (rest, captured) = pcap_parser
            .next_packet(remaining)
            .map_err(|error| format!("Could not read packet {}: {error}", packet_count + 1))?;
        packet_count += 1;

        let (unparsed, packet) = parse_packet(&packet_parser, header.datalink, &captured.data)
            .map_err(|error| format!("Could not decode packet {packet_count}: {error:?}"))?;

        writeln!(
            &mut output,
            "Packet {packet_count} (timestamp: {:?}, captured: {} bytes, original: {} bytes):\n{packet:#?}",
            captured.timestamp,
            captured.data.len(),
            captured.orig_len,
        )
        .expect("writing to a String cannot fail");

        if !unparsed.is_empty() {
            writeln!(&mut output, "Unparsed trailing bytes: {}", unparsed.len())
                .expect("writing to a String cannot fail");
        }
        output.push('\n');
        remaining = rest;
    }

    writeln!(&mut output, "Parsed {packet_count} packet(s).")
        .expect("writing to a String cannot fail");
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::read_packets_debug;

    #[test]
    fn formats_each_packet_as_debug_output() {
        let capture = include_bytes!("../../tests/pcaps/test_pcap_read_write.pcap");
        let output = read_packets_debug(capture).unwrap();

        assert!(output.contains("Packet 1"));
        assert!(output.contains("Ether"));
        assert!(output.contains("Parsed 14 packet(s)."));
    }
}
