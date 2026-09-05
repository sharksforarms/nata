/*!
Nata is a network packet manipulation toolkit.

This library takes inspiration from Python's [Scapy](https://scapy.net/).

Nata enables extensible parsing and crafting of network packets.

# Layer

A [`PacketLayer`](crate::layer::PacketLayer) represents the layout structure
of a specific protocol (such as [Tcp](crate::layer::tcp::Tcp)).

Nata has [layer implementations](./layer/trait.PacketLayer.html#implementors)
for many core network protocols.

For custom protocols or those implemented in nata already, see [layer] for examples on adding a new layer.

If you think a protocol should be included by default in nata, consider contributing! See [here](https://github.com/sharksforarms/nata) for more information.

## Example

```rust
use nata::layer::PacketLayer;
use nata::layer::ether::{Ether, EtherType, MacAddress};
# use hexlit::hex;

let data: &[u8] = &hex!("feff200001000000010000000800");

let (_rest, ether) = Ether::parse(data).unwrap();

assert_eq!(Ether {
    src: MacAddress([0x00, 0x00, 0x01, 0x00, 0x00, 0x00]),
    dst: MacAddress([0xfe, 0xff, 0x20, 0x00, 0x01, 0x00]),
    ether_type: EtherType::IPv4,
}, ether);


let ether_bytes = ether.to_bytes().unwrap();
assert_eq!(data, ether_bytes);
```

# Packet

Data sent over a network such as the Internet, are split up into packets.

A [Packet](crate::packet::Packet) is defined as an ordered collection of
[PacketLayer](crate::layer::PacketLayer)s.

## Example

```rust

use nata::prelude::*;

let mut packet = Packet::builder()
    .layer(Ether::default())
    .layer(Ipv4::default())
    .layer(Tcp::default())
    .payload(b"hello world")
    .build()
    .unwrap();

// `bytes` updates length fields, offsets, and checksums before serializing.
let _bytes = packet.bytes().unwrap();

```

# Packet Parser

The packet parser defines the heuristics on which layer to parse next, given the current layer and
the remaining bytes.

Nata provides default bindings for the built-in layers. They cover Ethernet to
IPv4/IPv6, IPv4/IPv6 to TCP/UDP/ICMP, and transport protocols to raw payloads.

```rust
use nata::packet::Parser;
use nata::layer::{
    PacketLayer,
    ether::Ether,
    ip::ipv4::Ipv4,
    tcp::Tcp,
};
# use hexlit::hex;
# use nata::layer::{LayerOwned, LayerError};

// My custom Http layer
#[derive(Debug, Clone)]
struct Http {}

impl PacketLayer for Http {
    // ...
#     fn finalize(&mut self, prev: &[LayerOwned], _next: &[LayerOwned]) -> Result<(), LayerError> {
#         Ok(())
#     }
#
#     fn parse(input: &[u8]) -> Result<(&[u8], Self), LayerError>
#     where
#         Self: Sized,
#     {
#         let http = Http {};
#         Ok(([].as_ref(), http))
#     }
#
#     fn to_bytes(&self) -> Result<Vec<u8>, LayerError> {
#         unimplemented!()
#     }
}

let parser = Parser::new()
    .bind::<Tcp, Http>(|tcp, _rest| tcp.dport == 80);

// Ether / IP / TCP / "GET /example HTTP/1.1"
let test_data = hex!("ffffffffffff0000000000000800450000330001000040067cc27f0000017f00000100140050000000000000000050022000ffa20000474554202f6578616d706c6520485454502f312e31");
let packet = parser.parse::<Ether>(&test_data).unwrap();

assert_eq!("Ether / Ipv4 / Tcp / Http", packet.summary());
```

# Interface

An [Interface](crate::datalink::Interface) provides the circuitry necessary to perform I/O with packets.

This could be reading/writing from/to a network interface, a pcap file, or other.

See [here](crate::datalink) for more information.


## Example

```rust,no_run
#[cfg(feature = "std")]
fn main() {
use nata::{datalink::Interface, prelude::*};

// Read from a live interface using the configured backend
let mut int = Interface::open("lo").unwrap();

let (mut rx, mut _tx) = int.into_split();

for pkt in rx.try_iter() {
    println!("Packet: {:?}", pkt.unwrap());
}
}

#[cfg(not(feature = "std"))]
fn main() {}
```

*/
#![cfg_attr(not(feature = "std"), no_std)]
#![warn(missing_docs)]

extern crate alloc;

#[cfg(test)]
#[macro_use]
extern crate std;

pub mod layer;
pub mod packet;

/// Parse an Ethernet packet using the built-in layer bindings.
pub fn parse(input: &[u8]) -> Result<packet::Packet, packet::PacketError> {
    packet::PacketParser::new().parse::<layer::ether::Ether>(input)
}

/// Parse an Ethernet packet, returning any unparsed trailing bytes.
pub fn parse_partial(input: &[u8]) -> Result<(&[u8], packet::Packet), packet::PacketError> {
    packet::PacketParser::new().parse_partial::<layer::ether::Ether>(input)
}

/// Convenient imports for packet construction, parsing, inspection, and I/O.
pub mod prelude {
    pub use crate::layer::{
        ether::{Ether, EtherType, MacAddress},
        icmp::{Icmp4, IcmpType},
        ip::{IpProtocol, Ipv4, Ipv6},
        raw::Raw,
        tcp::{Tcp, TcpFlags, TcpOption},
        udp::Udp,
        IntoLayer, LayerOwned, PacketLayer,
    };
    pub use crate::packet::{
        IntoPacket, Packet, PacketBuilder, PacketError, PacketParser, PacketRef, Parser,
    };
    pub use crate::{parse, parse_partial};

    #[cfg(feature = "std")]
    pub use crate::datalink::{Interface, PacketRead, PacketReadExt, PacketWrite};
}

#[cfg(feature = "std")]
pub mod datalink;
