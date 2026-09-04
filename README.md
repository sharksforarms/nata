<p align="center">
  <img src=".github/assets/nata-mascot.png" alt="Nata mascot" width="320">
</p>

<p align="center">
  <a href="https://crates.io/crates/nata"><img src="https://img.shields.io/crates/v/nata.svg" alt="Latest Version"></a>
  <a href="https://docs.rs/nata"><img src="https://docs.rs/nata/badge.svg" alt="Rust Documentation"></a>
  <a href="https://github.com/sharksforarms/nata/actions/workflows/main.yml"><img src="https://github.com/sharksforarms/nata/actions/workflows/main.yml/badge.svg" alt="CI Status"></a>
  <a href="https://codecov.io/gh/sharksforarms/nata"><img src="https://codecov.io/gh/sharksforarms/nata/branch/master/graph/badge.svg" alt="codecov"></a>
</p>

Nata is a Rust library for parsing, inspecting, constructing, and writing
network packets. It takes inspiration from [Scapy](https://scapy.net/) and
provides strongly typed protocol layers with symmetric binary serialization.

## Capabilities

- Parse and serialize typed protocol layers.
- Build packets and finalize dependent lengths and checksums.
- Register custom layer bindings and define new protocols.
- Capture live packets, read PCAP/PCAPNG and gzip-compressed captures, and
  write PCAP files.
- Use the core packet APIs in `no_std` applications.

## Install

```toml
[dependencies]
nata = "0.1"
```

See [Features](#features) for optional integrations and `no_std` configuration.

## Quick start

Build and parse an Ethernet/IPv4/UDP packet:

```rust
use nata::{
    is_layer,
    layer::{
        ether::{Ether, EtherType, MacAddress},
        ip::{IpProtocol, Ipv4},
        raw::Raw,
        udp::Udp,
        LayerOwned,
    },
    packet::{Packet, PacketParser},
};

fn main() {
    let layers: Vec<LayerOwned> = vec![
        Box::new(Ether {
            dst: MacAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x02]),
            src: MacAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]),
            ether_type: EtherType::IPv4,
        }),
        Box::new(Ipv4 {
            src: 0xc000_0201, // 192.0.2.1
            dst: 0xc633_6402, // 198.51.100.2
            ttl: 64,
            protocol: IpProtocol::UDP,
            ..Ipv4::default()
        }),
        Box::new(Udp {
            sport: 40_000,
            dport: 53,
            ..Udp::default()
        }),
        Box::new(Raw {
            data: b"hello from nata".to_vec(),
            ..Raw::default()
        }),
    ];

    let mut packet = Packet::from_layers(layers);
    packet.finalize().unwrap();

    let bytes = packet.to_bytes().unwrap();
    let (rest, parsed) = PacketParser::new().parse_packet::<Ether>(&bytes).unwrap();

    assert!(rest.is_empty());
    assert_eq!(parsed.layers().len(), 4);
    assert!(is_layer!(parsed.layers()[0], Ether));
    assert!(is_layer!(parsed.layers()[1], Ipv4));
    assert!(is_layer!(parsed.layers()[2], Udp));
    assert!(is_layer!(parsed.layers()[3], Raw));
}
```

See the complete runnable version in
[`examples/build_packet.rs`](examples/build_packet.rs). For custom layers,
capture-file processing, and live packet capture and injection, see the [API
documentation](https://docs.rs/nata) and
[examples](https://github.com/sharksforarms/nata/tree/master/examples).

## Features

`std` is enabled by default. It provides live interfaces through libpnet and
offline capture-file reading for PCAP/PCAPNG files, including gzip-compressed
input. Live libpcap support is optional.

| Feature | Default | Description |
| --- | --- | --- |
| `std` | Yes | Live interfaces, PCAP/PCAPNG reading, and PCAP writing |
| `libpcap` | No | Live capture and injection through libpcap |

Enable live libpcap support with:

```toml
[dependencies]
nata = { version = "0.1", default-features = false, features = ["std", "libpcap"] }
```

For `no_std` applications, disable the default features:

```toml
[dependencies]
nata = { version = "0.1", default-features = false }
```

Packet types use allocation, so `no_std` applications must provide an
allocator. See the `example_no_std` fixture.

The `libpcap` feature requires libpcap development files.

## Built-in layers

- Ethernet II: `Ether`, `EtherType`, `MacAddress`
- IP: `Ipv4`, `Ipv6`, `IpProtocol`, `Ipv4Option`
- ICMPv4: `Icmp4`, `IcmpType`
- TCP: `Tcp`, `TcpFlags`, `TcpOption`
- UDP: `Udp`
- Raw payload: `Raw`

`PacketParser::new()` binds Ethernet to IPv4/IPv6, IP to ICMPv4/TCP/UDP, and
TCP/UDP to `Raw`. Unknown protocols fall back to `Raw`. Use
`PacketParser::bind_layer` to add application protocols.

## Examples

- [Build and parse a packet](examples/build_packet.rs)
- [Define a custom layer](examples/custom_layer.rs)
- [Read and write a PCAP file](examples/read_write_pcap.rs)
- [Capture and inject packets](examples/spoof_http_server.rs)

See the [API documentation](https://docs.rs/nata) for the complete API.

## Development

Run the stable CI pipeline inside the cached Docker environment:

```sh
docker compose run --rm build just ci-stable
```

List the available build, test, lint, and coverage commands with:

```sh
docker compose run --rm build just
```

Run only the TShark compatibility suite with:

```sh
docker compose run --rm build just tshark-test
```

The container includes the pinned TShark version and fetches the pinned
Wireshark capture corpus when needed.

## License

Licensed under either the
[MIT license](https://github.com/sharksforarms/nata/blob/master/LICENSE-MIT) or
[Apache License 2.0](https://github.com/sharksforarms/nata/blob/master/LICENSE-APACHE).
