use crate::layer_fields::{set_field, set_layer_fields, JsonFields};
use nata::{
    datalink::pcapfile::{CapturePacket, PcapFileReader},
    layer::{
        ether::Ether,
        ip::{Ipv4, Ipv6},
    },
    packet::{Packet, PacketParser},
};
use pcap_file::DataLink;
use serde_json::Value;
use std::path::Path;

pub(crate) fn read_capture(path: &Path) -> Result<Vec<CapturePacket>, String> {
    let filename = path
        .to_str()
        .ok_or_else(|| format!("capture path is not valid UTF-8: {}", path.display()))?;
    let mut reader = PcapFileReader::new(filename, PacketParser::new())
        .map_err(|error| format!("could not open capture {}: {error:?}", path.display()))?;
    let mut packets = Vec::new();

    while let Some(packet) = reader
        .next_capture_packet()
        .map_err(|error| format!("could not read capture {}: {error:?}", path.display()))?
    {
        packets.push(packet);
    }

    Ok(packets)
}

fn parse_packet(parser: &PacketParser, capture_packet: &CapturePacket) -> Result<Packet, String> {
    let data = capture_packet.data.as_slice();
    let parsed = match capture_packet.link_type {
        DataLink::ETHERNET => parser.parse_packet::<Ether>(data).map(|(_, packet)| packet),
        DataLink::IPV4 => parser.parse_packet::<Ipv4>(data).map(|(_, packet)| packet),
        DataLink::IPV6 => parser.parse_packet::<Ipv6>(data).map(|(_, packet)| packet),
        DataLink::RAW => match data.first().map(|byte| byte >> 4) {
            Some(4) => parser.parse_packet::<Ipv4>(data).map(|(_, packet)| packet),
            Some(6) => parser.parse_packet::<Ipv6>(data).map(|(_, packet)| packet),
            Some(version) => return Err(format!("unsupported raw IP version {version}")),
            None => return Err("empty raw packet".to_string()),
        },
        link_type => return Err(format!("unsupported link type {link_type:?}")),
    };

    parsed.map_err(|error| format!("Nata packet parse failed: {error:?}"))
}

pub(crate) fn render_json(capture: &[CapturePacket]) -> Result<Value, String> {
    let parser = PacketParser::new();
    let mut packets = Vec::with_capacity(capture.len());

    for (index, capture_packet) in capture.iter().enumerate() {
        let packet = parse_packet(&parser, capture_packet)?;
        packets.push(packet_fields(&packet, capture_packet, index + 1)?);
    }

    serde_json::to_value(packets).map_err(|error| format!("could not serialize Nata JSON: {error}"))
}

fn packet_fields(
    packet: &Packet,
    capture_packet: &CapturePacket,
    packet_number: usize,
) -> Result<JsonFields, String> {
    let mut fields = JsonFields::new();
    set_field(&mut fields, "frame.number", packet_number.to_string());
    set_field(
        &mut fields,
        "frame.len",
        capture_packet.original_len.to_string(),
    );
    set_field(
        &mut fields,
        "frame.cap_len",
        capture_packet.data.len().to_string(),
    );

    for layer in packet.layers() {
        set_layer_fields(layer.as_ref(), &mut fields)?;
    }

    Ok(fields)
}
