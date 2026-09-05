use deku::prelude::DekuContainerWrite;
use nata::{
    get_layer,
    layer::{
        ether::{Ether, MacAddress},
        icmp::{Icmp4, IcmpType},
        ip::{IpProtocol, Ipv4, Ipv6},
        raw::Raw,
        tcp::{Tcp, TcpFlags},
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
        let bytes = LayerExt::to_bytes(self)
            .map_err(|error| format!("could not serialize Ethernet layer: {error:?}"))?;
        let ether_type = bytes
            .get(12..14)
            .and_then(|bytes| bytes.try_into().ok())
            .map(u16::from_be_bytes)
            .ok_or_else(|| "serialized Ethernet layer is shorter than 14 bytes".to_string())?;
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
            protocol_number(&self.protocol)?.to_string(),
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
            protocol_number(&self.next_header)?.to_string(),
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
        set_field(
            fields,
            "tcp.flags",
            format!("0x{:04x}", tcp_flags(&self.flags)),
        );
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
            icmp_type_number(&self.icmp_type)?.to_string(),
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
    fields.insert(name.to_string(), vec![value]);
}

fn protocol_number(protocol: &IpProtocol) -> Result<u8, String> {
    encoded_u8(protocol, "IP protocol")
}

fn icmp_type_number(icmp_type: &IcmpType) -> Result<u8, String> {
    encoded_u8(icmp_type, "ICMP type")
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

fn tcp_flags(flags: &TcpFlags) -> u16 {
    (u16::from(flags.reserved) << 9)
        | (u16::from(flags.nonce) << 8)
        | (u16::from(flags.crw) << 7)
        | (u16::from(flags.ecn) << 6)
        | (u16::from(flags.urgent) << 5)
        | (u16::from(flags.ack) << 4)
        | (u16::from(flags.push) << 3)
        | (u16::from(flags.reset) << 2)
        | (u16::from(flags.syn) << 1)
        | u16::from(flags.fin)
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

    #[test]
    fn tcp_flags_match_tshark_bit_values() {
        let flags = TcpFlags {
            syn: 1,
            ack: 1,
            ..Default::default()
        };

        assert_eq!(0x0012, tcp_flags(&flags));
    }
}
