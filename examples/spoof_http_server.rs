//! Minimal HTTP server built from captured and injected packets.
//!
//! This example handles a basic TCP handshake and a single-segment HTTP GET.
//! It is intentionally educational rather than a complete TCP implementation:
//! retransmission, reassembly, congestion control, and multiple requests per
//! connection are outside its scope.
//!
//! Raw capture/injection normally requires root or equivalent capabilities.
//! The host TCP stack must also be prevented from sending RST packets for the
//! selected port. On Linux, for example:
//!
//! ```text
//! sudo iptables -A OUTPUT -p tcp --sport 8080 --tcp-flags RST RST -j DROP
//! sudo cargo run --example spoof_http_server -- eth0 192.0.2.10 8080
//! sudo iptables -D OUTPUT -p tcp --sport 8080 --tcp-flags RST RST -j DROP
//! ```

use hatchet::{
    datalink::{pcap::Pcap, Interface, PacketWrite},
    get_layer,
    layer::{
        ether::{Ether, EtherType, MacAddress},
        ip::{IpProtocol, Ipv4},
        raw::Raw,
        tcp::{Tcp, TcpFlags},
        LayerOwned,
    },
    packet::Packet,
};
use std::{convert::TryFrom, env, net::Ipv4Addr, process};

const DEFAULT_PORT: u16 = 8080;
const SERVER_INITIAL_SEQUENCE: u32 = 0x4841_5443;
const HTTP_RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\n\
Content-Type: text/plain\r\n\
Content-Length: 20\r\n\
Connection: close\r\n\
\r\n\
Hello from Hatchet!\n";

struct Reply<'a> {
    sequence: u32,
    acknowledgment: u32,
    flags: TcpFlags,
    payload: &'a [u8],
}

fn usage(program: &str) -> ! {
    eprintln!("usage: {program} <interface> <server-ipv4> [port]");
    process::exit(2);
}

fn tcp_payload<'a>(ipv4: &Ipv4, tcp: &Tcp, raw: Option<&'a Raw>) -> &'a [u8] {
    let ip_header_length = usize::from(ipv4.ihl) * 4;
    let tcp_header_length = usize::from(tcp.offset) * 4;
    let payload_length = usize::from(ipv4.length)
        .saturating_sub(ip_header_length)
        .saturating_sub(tcp_header_length);
    let captured = raw.map_or(&[][..], |raw| raw.data.as_slice());

    &captured[..payload_length.min(captured.len())]
}

fn next_client_sequence(tcp: &Tcp, payload_length: usize) -> u32 {
    tcp.seq
        .wrapping_add(u32::try_from(payload_length).unwrap_or(u32::MAX))
        .wrapping_add(u32::from(tcp.flags.syn))
        .wrapping_add(u32::from(tcp.flags.fin))
}

fn build_reply(
    request_ether: &Ether,
    server_mac: &MacAddress,
    request_ipv4: &Ipv4,
    request_tcp: &Tcp,
    reply: Reply<'_>,
) -> Packet {
    let mut layers: Vec<LayerOwned> = vec![
        Box::new(Ether {
            dst: request_ether.src.clone(),
            src: server_mac.clone(),
            ether_type: EtherType::IPv4,
        }),
        Box::new(Ipv4 {
            src: request_ipv4.dst,
            dst: request_ipv4.src,
            ttl: 64,
            protocol: IpProtocol::TCP,
            identification: request_ipv4.identification.wrapping_add(1),
            flags: 0b010,
            ..Ipv4::default()
        }),
        Box::new(Tcp {
            sport: request_tcp.dport,
            dport: request_tcp.sport,
            seq: reply.sequence,
            ack: reply.acknowledgment,
            flags: reply.flags,
            window: 64_240,
            ..Tcp::default()
        }),
    ];

    if !reply.payload.is_empty() {
        layers.push(Box::new(Raw {
            data: reply.payload.to_vec(),
            ..Raw::default()
        }));
    }

    let mut reply = Packet::from_layers(layers);
    reply.finalize().expect("failed to finalize reply packet");
    reply
}

fn main() {
    let mut args = env::args();
    let program = args.next().unwrap_or_else(|| "http_server".to_string());
    let interface_name = args.next().unwrap_or_else(|| usage(&program));
    let server_ip = args
        .next()
        .unwrap_or_else(|| usage(&program))
        .parse::<Ipv4Addr>()
        .unwrap_or_else(|_| usage(&program));
    let port = args
        .next()
        .map(|port| port.parse::<u16>().unwrap_or_else(|_| usage(&program)))
        .unwrap_or(DEFAULT_PORT);

    if args.next().is_some() {
        usage(&program);
    }

    let server_ip = u32::from(server_ip);
    let mut interface = Interface::init::<Pcap>(&interface_name)
        .unwrap_or_else(|error| panic!("failed to open {}: {:?}", interface_name, error));
    let server_mac = interface
        .mac_address()
        .cloned()
        .expect("interface does not have a MAC address");
    let (mut reader, mut writer) = interface.split();

    println!("listening on {interface_name}, port {port}");

    for packet in &mut reader {
        let ether = packet
            .layers()
            .iter()
            .find_map(|layer| get_layer!(layer, Ether));
        let ipv4 = packet
            .layers()
            .iter()
            .find_map(|layer| get_layer!(layer, Ipv4));
        let tcp = packet
            .layers()
            .iter()
            .find_map(|layer| get_layer!(layer, Tcp));
        let raw = packet
            .layers()
            .iter()
            .find_map(|layer| get_layer!(layer, Raw));

        let (Some(ether), Some(ipv4), Some(tcp)) = (ether, ipv4, tcp) else {
            continue;
        };

        if ipv4.dst != server_ip || tcp.dport != port {
            continue;
        }

        let payload = tcp_payload(ipv4, tcp, raw);

        if tcp.flags.syn == 1 && tcp.flags.ack == 0 {
            let syn_ack = build_reply(
                ether,
                &server_mac,
                ipv4,
                tcp,
                Reply {
                    sequence: SERVER_INITIAL_SEQUENCE,
                    acknowledgment: next_client_sequence(tcp, payload.len()),
                    flags: TcpFlags {
                        syn: 1,
                        ack: 1,
                        ..TcpFlags::default()
                    },
                    payload: &[],
                },
            );
            writer.write(syn_ack).expect("failed to inject SYN-ACK");
            continue;
        }

        if tcp.flags.ack == 1 && payload.starts_with(b"GET ") {
            let response = build_reply(
                ether,
                &server_mac,
                ipv4,
                tcp,
                Reply {
                    sequence: tcp.ack,
                    acknowledgment: next_client_sequence(tcp, payload.len()),
                    flags: TcpFlags {
                        ack: 1,
                        push: 1,
                        fin: 1,
                        ..TcpFlags::default()
                    },
                    payload: HTTP_RESPONSE,
                },
            );
            writer
                .write(response)
                .expect("failed to inject HTTP response");
            println!("served {}:{}", Ipv4Addr::from(ipv4.src), tcp.sport);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hatchet::packet::PacketParser;

    #[test]
    fn builds_parseable_http_response() {
        let request_ether = Ether {
            src: MacAddress([0x02, 0, 0, 0, 0, 1]),
            dst: MacAddress([0x02, 0, 0, 0, 0, 2]),
            ether_type: EtherType::IPv4,
        };
        let request_ipv4 = Ipv4 {
            src: 0xc000_0201,
            dst: 0xc633_6402,
            protocol: IpProtocol::TCP,
            ..Ipv4::default()
        };
        let request_tcp = Tcp {
            sport: 50_000,
            dport: DEFAULT_PORT,
            seq: 100,
            ack: 200,
            ..Tcp::default()
        };

        let reply = build_reply(
            &request_ether,
            &request_ether.dst,
            &request_ipv4,
            &request_tcp,
            Reply {
                sequence: request_tcp.ack,
                acknowledgment: 118,
                flags: TcpFlags {
                    ack: 1,
                    push: 1,
                    fin: 1,
                    ..TcpFlags::default()
                },
                payload: HTTP_RESPONSE,
            },
        );
        let bytes = reply.to_bytes().unwrap();
        let (rest, parsed) = PacketParser::new().parse_packet::<Ether>(&bytes).unwrap();

        assert!(rest.is_empty());
        let tcp = get_layer!(parsed.layers()[2], Tcp).unwrap();
        let raw = get_layer!(parsed.layers()[3], Raw).unwrap();
        assert_eq!(tcp.sport, DEFAULT_PORT);
        assert_eq!(tcp.dport, 50_000);
        assert_eq!(tcp.flags.ack, 1);
        assert_eq!(tcp.flags.push, 1);
        assert_eq!(tcp.flags.fin, 1);
        assert_ne!(tcp.checksum, 0);
        assert_eq!(raw.data, HTTP_RESPONSE);
    }
}
