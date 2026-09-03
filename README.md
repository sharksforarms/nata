# Nata

[![Latest Version](https://img.shields.io/crates/v/nata.svg)](https://crates.io/crates/nata)
[![Rust Documentation](https://docs.rs/nata/badge.svg)](https://docs.rs/nata)
[![Actions Status](https://github.com/sharksforarms/nata/workflows/CI/badge.svg)](https://github.com/sharksforarms/nata/actions)
[![codecov](https://codecov.io/gh/sharksforarms/nata/branch/master/graph/badge.svg)](https://codecov.io/gh/sharksforarms/nata)

Nata is a Rust toolkit for parsing, inspecting, constructing, and writing
network packets. It takes inspiration from [Scapy](https://scapy.net/) while
providing strongly typed protocol layers and symmetric binary serialization.

## Capabilities

- Parse raw bytes into typed protocol layers and serialize them back to bytes.
- Compose packets from independently configurable layers.
- Finalize dependent fields such as IPv4 lengths, transport lengths, header
  checksums, and TCP/UDP checksums.
- Parse complete protocol stacks with built-in layer bindings, or register
  custom bindings for application protocols.
- Add custom protocols by implementing the `Layer` and `LayerExt` traits.
- Read and write live interfaces through libpcap or pnet, and read or write
  PCAP files.
- Compile the core packet and layer APIs without `std`.

## Usage

```toml
[dependencies]
nata = "0.1"
```

Disable the default standard-library integrations for `no_std` applications:

```toml
[dependencies]
nata = { version = "0.1", default-features = false }
```

Nata's packet representation uses allocation-backed types, so the
application must provide an allocator. The
[`example_no_std`](example_no_std/README.md) fixture demonstrates this in a
real Cortex-M application and is cross-compiled for two bare-metal targets in
CI.

## Quick start

The example below creates an Ethernet/IPv4/UDP packet containing a raw payload.
`finalize` fills in the dependent length and checksum fields before the packet
is serialized. The resulting bytes are then parsed back into the same four
layers.

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

The same program is available as [`examples/build_packet.rs`](examples/build_packet.rs).

See the [API documentation](https://docs.rs/nata) and
[examples](https://github.com/sharksforarms/nata/tree/master/examples) for
custom layers, offline PCAP processing, and live packet capture and injection.

## Cargo features

The default feature set selects `std` and `pcap`.

| Feature | Default | Description |
| --- | --- | --- |
| `std` | Yes | Standard-library data-link APIs, including pnet live interfaces and offline PCAP file I/O |
| `pcap` | Yes | Live packet capture and injection through libpcap; used together with `std` |
| `netmap` | No | Enables pnet's netmap backend; used together with `std` |

To use offline PCAP files and pnet interfaces without linking libpcap, enable
only `std`:

```toml
[dependencies]
nata = { version = "0.1", default-features = false, features = ["std"] }
```

Netmap support is opt-in:

```toml
[dependencies]
nata = { version = "0.1", default-features = false, features = ["std", "netmap"] }
```

The live backends have native prerequisites: `pcap` requires the libpcap
library and development headers, while `netmap` requires a netmap-enabled
system and its headers. Offline PCAP file I/O does not require either backend.

## `no_std`

Nata's packet, parser, and protocol-layer APIs support `no_std` with
allocation. Disable the default features to remove the standard-library,
live-interface, and PCAP-file integrations:

```toml
[dependencies]
nata = { version = "0.1", default-features = false }
```

The core API uses allocation-backed types such as `Box` and `Vec`, so embedded
targets must provide a global allocator. Packet parsing, construction,
serialization, finalization, and custom layers remain available. The
[`example_no_std`](example_no_std) crate is built by CI to verify this
configuration. The same core-only configuration is also used by the
[`example_wasm`](example_wasm) WebAssembly fixture.

## Built-in layers

- Ethernet II (`Ether`, `EtherType`, `MacAddress`)
- IPv4 (`Ipv4`, `IpProtocol`, `Ipv4Option`)
- IPv6 (`Ipv6`, `IpProtocol`)
- ICMPv4 (`Icmp4`, `IcmpType`)
- TCP (`Tcp`, `TcpFlags`, `TcpOption`)
- UDP (`Udp`)
- Raw payload data (`Raw`)

`PacketParser::new()` includes bindings for Ethernet to IPv4/IPv6, IP to
ICMPv4/TCP/UDP, and TCP/UDP to raw payload data. Unknown protocols fall back to
`Raw`. Additional bindings can be registered with `PacketParser::bind_layer`,
allowing application protocols to participate in the same parsing pipeline.

## I/O integrations

With `std` enabled, Nata provides a common interface abstraction for:

- Live packet capture and injection through libpcap (`pcap` feature).
- Live interfaces through pnet.
- Offline PCAP file reading and writing.

The parsing and construction APIs do not require an interface and can be used
directly with byte slices and byte vectors.

See [`examples/read_write_pcap.rs`](examples/read_write_pcap.rs) for portable,
offline packet reading and writing. For a live-network example, see
[`examples/spoof_http_server.rs`](examples/spoof_http_server.rs), a minimal HTTP
server built with packet capture and Ethernet/IPv4/TCP/Raw packet injection.

## Development

Run the same checks as CI inside the cached Docker environment:

```sh
docker compose run --rm build just ci
```

List the available build, test, lint, and coverage commands with:

```sh
docker compose run --rm build just
```

## License

Licensed under either the
[MIT license](https://github.com/sharksforarms/nata/blob/master/LICENSE-MIT) or
[Apache License 2.0](https://github.com/sharksforarms/nata/blob/master/LICENSE-APACHE).
