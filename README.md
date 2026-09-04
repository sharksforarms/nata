<p align="center">
  <img src=".github/assets/nata-mascot.png" alt="Nata mascot" width="320">
</p>

<p align="center">
  <a href="https://crates.io/crates/nata"><img src="https://img.shields.io/crates/v/nata.svg" alt="Latest Version"></a>
  <a href="https://docs.rs/nata"><img src="https://docs.rs/nata/badge.svg" alt="Rust Documentation"></a>
  <a href="https://github.com/sharksforarms/nata/actions/workflows/main.yml"><img src="https://github.com/sharksforarms/nata/actions/workflows/main.yml/badge.svg" alt="CI Status"></a>
  <a href="https://codecov.io/gh/sharksforarms/nata"><img src="https://codecov.io/gh/sharksforarms/nata/branch/master/graph/badge.svg" alt="codecov"></a>
</p>

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
- Add custom protocols by implementing the `PacketLayer` trait.
- Read and write live packets and offline PCAP files.
- Compile the core packet and layer APIs without `std`.

## Usage

```toml
[dependencies]
nata = "0.1"
```

See [Cargo features](#cargo-features) for optional integrations and `no_std`
configuration.

## Quick start

The high-level API creates an Ethernet/IPv4/UDP packet containing a raw
payload without exposing `Box<dyn ...>` layer storage. `build` finalizes
dependent length, offset, and checksum fields. `bytes` is also safe to call on
an unfinished packet and finalizes it first.

```rust
use nata::prelude::*;
use std::net::Ipv4Addr;

fn main() {
    let mut packet = Packet::builder()
        .layer(Ether::new(
            MacAddress::new([0x02, 0, 0, 0, 0, 1]),
            MacAddress::new([0x02, 0, 0, 0, 0, 2]),
        ))
        .layer(
            Ipv4::new(
                Ipv4Addr::new(192, 0, 2, 1),
                Ipv4Addr::new(198, 51, 100, 2),
            )
            .protocol(IpProtocol::UDP),
        )
        .layer(Udp::new(40_000, 53))
        .payload(b"hello from nata")
        .build()
        .unwrap();

    let bytes = packet.bytes().unwrap();
    let parsed = parse(&bytes).unwrap();

    assert_eq!(parsed.as_ref().len(), 4);
    assert_eq!("Ether / Ipv4 / Udp / Raw", parsed.summary());
}
```

The same program is available as [`examples/build_packet.rs`](examples/build_packet.rs).

For Scapy-style composition, convert the first layer into a packet and use
`/` for subsequent layers:

```rust
let mut packet = Ether::default().into_packet()
    / Ipv4::default()
    / Udp::new(40_000, 53)
    / Raw::new(b"hello");

let bytes = packet.bytes().unwrap();
```

`packet.get::<Tcp>()`, `packet.get_mut::<Ipv4>()`, `packet.has::<Raw>()`, and
`packet.as_ref()` provide typed inspection.
`PacketRef` is a read-only borrowed view; it does not clone or own layers.

`bytes` and `into_bytes` finalize before serializing. The lower-level
`PacketLayer::to_bytes` method is the implementation hook for custom layers;
normal packet construction should use the packet methods above. Packet writers
call `bytes` automatically.

See the [API documentation](https://docs.rs/nata) and
[examples](https://github.com/sharksforarms/nata/tree/master/examples) for
custom layers, offline PCAP processing, and live packet capture and injection.

## Cargo features

Nata enables `std` by default. This provides libpnet interfaces and offline PCAP
file I/O. Live libpcap support is opt-in.

| Feature | Default | Description |
| --- | --- | --- |
| `std` | Yes | Live interfaces through libpnet and offline PCAP file I/O |
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

`libpcap` requires its development files.

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
For the common typed case, use `Parser::bind`:

```rust
let parser = Parser::new()
    .bind::<Tcp, Http>(|tcp, _rest| tcp.dport == 80);
let packet = parser.parse::<Ether>(&bytes).unwrap();
```

`parse` requires the input to be fully consumed. Use `parse_partial` when a
caller needs the remaining bytes. `bind_layer` remains available for advanced
bindings where the next layer type is selected dynamically.

## I/O integrations

Packet parsing and construction work directly with byte slices and do not
require a network interface.

See [`examples/read_write_pcap.rs`](examples/read_write_pcap.rs) for portable,
offline packet I/O. `PcapFile::open` and `PcapFile::create` provide convenient
entry points, while `try_iter` preserves read and parse errors. For live packet
I/O, see
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
