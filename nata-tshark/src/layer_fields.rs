use deku::prelude::DekuContainerWrite;
use nata::{
    get_layer,
    layer::{
        ether::{Ether, MacAddress},
        icmp::{Icmp4, IcmpType},
        ip::{Ipv4, Ipv6},
        raw::Raw,
        tcp::Tcp,
        udp::Udp,
        LayerExt,
    },
};
use std::{
    collections::BTreeMap,
    convert::TryInto,
    net::{Ipv4Addr, Ipv6Addr},
};

pub(crate) type JsonFields = BTreeMap<String, Vec<String>>;

/// Converts one Nata layer into the fields used by the TShark comparison.
pub(crate) trait TsharkFields {
    fn set_fields(&self, fields: &mut JsonFields) -> Result<(), String>;
}

pub(crate) fn set_layer_fields(
    layer: &dyn LayerExt,
    fields: &mut JsonFields,
) -> Result<(), String> {
    if let Some(layer_value) = get_layer!(layer, Ether) {
        return layer_value.set_fields(fields);
    }
    if let Some(layer_value) = get_layer!(layer, Ipv4) {
        return layer_value.set_fields(fields);
    }
    if let Some(layer_value) = get_layer!(layer, Ipv6) {
        return layer_value.set_fields(fields);
    }
    if let Some(layer_value) = get_layer!(layer, Tcp) {
        return layer_value.set_fields(fields);
    }
    if let Some(layer_value) = get_layer!(layer, Udp) {
        return layer_value.set_fields(fields);
    }
    if let Some(layer_value) = get_layer!(layer, Icmp4) {
        return layer_value.set_fields(fields);
    }
    if let Some(layer_value) = get_layer!(layer, Raw) {
        return layer_value.set_fields(fields);
    }

    Err(format!("no TShark field adapter for Nata layer: {layer:?}"))
}

impl TsharkFields for Ether {
    fn set_fields(&self, fields: &mut JsonFields) -> Result<(), String> {
        set_field(fields, "eth.src", format_mac(&self.src));
        set_field(fields, "eth.dst", format_mac(&self.dst));
        let ether_type = encoded_u16(&self.ether_type, "Ethernet type")?;
        set_field(fields, "eth.type", format!("0x{ether_type:04x}"));
        Ok(())
    }
}

impl TsharkFields for Ipv4 {
    fn set_fields(&self, fields: &mut JsonFields) -> Result<(), String> {
        set_field(fields, "ip.version", self.version.to_string());
        set_field(fields, "ip.hdr_len", (self.ihl * 4).to_string());
        set_field(
            fields,
            "ip.dsfield",
            format!("0x{:02x}", (self.dscp << 2) | self.ecn),
        );
        set_field(fields, "ip.len", self.length.to_string());
        set_field(fields, "ip.id", format!("0x{:04x}", self.identification));
        set_field(fields, "ip.flags", format!("0x{:02x}", self.flags));
        set_field(fields, "ip.frag_offset", (self.offset * 8).to_string());
        set_field(fields, "ip.ttl", self.ttl.to_string());
        set_field(
            fields,
            "ip.proto",
            encoded_u8(&self.protocol, "IP protocol")?.to_string(),
        );
        set_field(fields, "ip.checksum", format!("0x{:04x}", self.checksum));
        set_field(fields, "ip.src", Ipv4Addr::from(self.src).to_string());
        set_field(fields, "ip.dst", Ipv4Addr::from(self.dst).to_string());
        Ok(())
    }
}

impl TsharkFields for Ipv6 {
    fn set_fields(&self, fields: &mut JsonFields) -> Result<(), String> {
        set_field(fields, "ip.version", self.version.to_string());
        set_field(fields, "ipv6.version", self.version.to_string());
        set_field(
            fields,
            "ipv6.tclass",
            format!("0x{:08x}", (u32::from(self.ds) << 2) | u32::from(self.ecn)),
        );
        set_field(fields, "ipv6.flow", format!("0x{:06x}", self.label));
        set_field(fields, "ipv6.plen", self.length.to_string());
        set_field(
            fields,
            "ipv6.nxt",
            encoded_u8(&self.next_header, "IP protocol")?.to_string(),
        );
        set_field(fields, "ipv6.hlim", self.hop_limit.to_string());
        set_field(fields, "ipv6.src", Ipv6Addr::from(self.src).to_string());
        set_field(fields, "ipv6.dst", Ipv6Addr::from(self.dst).to_string());
        Ok(())
    }
}

impl TsharkFields for Tcp {
    fn set_fields(&self, fields: &mut JsonFields) -> Result<(), String> {
        set_field(fields, "tcp.srcport", self.sport.to_string());
        set_field(fields, "tcp.dstport", self.dport.to_string());
        set_field(fields, "tcp.seq", self.seq.to_string());
        set_field(fields, "tcp.ack", self.ack.to_string());
        set_field(fields, "tcp.hdr_len", (self.offset * 4).to_string());
        let flags = encoded_u16(&self.flags, "TCP flags")? >> 4;
        set_field(fields, "tcp.flags", format!("0x{flags:04x}"));
        set_field(fields, "tcp.window_size_value", self.window.to_string());
        set_field(fields, "tcp.checksum", format!("0x{:04x}", self.checksum));
        set_field(fields, "tcp.urgent_pointer", self.urgptr.to_string());
        Ok(())
    }
}

impl TsharkFields for Udp {
    fn set_fields(&self, fields: &mut JsonFields) -> Result<(), String> {
        set_field(fields, "udp.srcport", self.sport.to_string());
        set_field(fields, "udp.dstport", self.dport.to_string());
        set_field(fields, "udp.length", self.length.to_string());
        set_field(fields, "udp.checksum", format!("0x{:04x}", self.checksum));
        Ok(())
    }
}

impl TsharkFields for Icmp4 {
    fn set_fields(&self, fields: &mut JsonFields) -> Result<(), String> {
        set_field(
            fields,
            "icmp.type",
            encoded_u8(&self.icmp_type, "ICMP type")?.to_string(),
        );
        set_field(fields, "icmp.code", self.code.to_string());
        set_field(fields, "icmp.checksum", format!("0x{:04x}", self.checksum));
        if matches!(self.icmp_type, IcmpType::EchoRequest | IcmpType::EchoReply) {
            set_field(
                fields,
                "icmp.ident",
                ((self.message >> 16) as u16).to_string(),
            );
            set_field(fields, "icmp.seq", (self.message as u16).to_string());
        }
        Ok(())
    }
}

impl TsharkFields for Raw {
    fn set_fields(&self, _fields: &mut JsonFields) -> Result<(), String> {
        Ok(())
    }
}

pub(crate) fn set_field(fields: &mut JsonFields, name: &str, value: String) {
    fields.entry(name.to_string()).or_default().push(value);
}

fn encoded_u8<T: DekuContainerWrite>(value: &T, name: &str) -> Result<u8, String> {
    let bytes = value
        .to_bytes()
        .map_err(|error| format!("could not serialize {name}: {error:?}"))?;
    bytes
        .first()
        .copied()
        .ok_or_else(|| format!("{name} serialized to no bytes"))
}

fn encoded_u16<T: DekuContainerWrite>(value: &T, name: &str) -> Result<u16, String> {
    let bytes = value
        .to_bytes()
        .map_err(|error| format!("could not serialize {name}: {error:?}"))?;
    let bytes: [u8; 2] = bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| format!("{name} serialized to {} bytes", bytes.len()))?;
    Ok(u16::from_be_bytes(bytes))
}

fn format_mac(address: &MacAddress) -> String {
    address
        .0
        .iter()
        .map(|value| format!("{value:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

#[cfg(test)]
mod tests {
    use super::*;
    use nata::layer::tcp::TcpFlags;

    #[test]
    fn tcp_flags_match_tshark_bit_values() {
        let flags = TcpFlags {
            syn: 1,
            ack: 1,
            ..Default::default()
        };

        assert_eq!(0x0012, encoded_u16(&flags, "TCP flags").unwrap() >> 4);
    }

    #[test]
    fn repeated_fields_are_preserved() {
        let mut fields = JsonFields::new();
        set_field(&mut fields, "ip.src", "192.0.2.1".to_string());
        set_field(&mut fields, "ip.src", "192.0.2.2".to_string());

        assert_eq!(
            Some(&vec!["192.0.2.1".to_string(), "192.0.2.2".to_string()]),
            fields.get("ip.src")
        );
    }
}
