/*!
Nata is a network packet manipulation toolkit.

This library takes inspiration from Python's [Scapy](https://scapy.net/).

Nata enables extensible parsing and crafting of network packets.

# Layer

A Layer represents the layout structure of a specific protocol (such as [Tcp](crate::layer::tcp::Tcp)).

Nata has [layer implementations](./layer/trait.LayerExt.html#implementors) for many core network protocols.

For custom protocols or those implemented in nata already, see [layer](crate::layer) for examples on adding a new layer.

If you think a protocol should be included by default in nata, consider contributing! See [here](https://github.com/sharksforarms/nata) for more information.

## Example

```rust
use nata::layer::LayerExt;
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

A [Packet](crate::packet::Packet) is defined as a collection of
[Layer](crate::layer::Layer).

## Example

```rust

use nata::packet::Packet;
use nata::layer::{
    LayerExt,
    LayerOwned,
    ether::Ether,
    ip::ipv4::Ipv4,
    tcp::Tcp,
    raw::Raw,
};

let layers: Vec<LayerOwned> = vec![
    Box::new(Ether::default()),
    Box::new(Ipv4::default()),
    Box::new(Tcp::default()),
    Box::new(Raw::parse(b"hello world").unwrap().1),
];

let mut packet = Packet::from_layers(layers);

// Update length fields, checksums, etc.
packet.finalize().unwrap();

```

# Packet Parser

The packet parser defines the heuristics on which layer to parse next, given the current layer and
the remaining bytes.

Nata provides default layer bindings for layers it implements. These can be found [here](crate::packet::bindings).

```rust
use nata::packet::PacketParser;
use nata::layer::{
    Layer,
    LayerExt,
    ether::Ether,
    ip::ipv4::Ipv4,
    tcp::Tcp,
};
use nata::is_layer;
# use hexlit::hex;
# use nata::layer::{LayerOwned, LayerError};

// My custom Http layer
#[derive(Debug, Clone)]
struct Http {}

impl Layer for Http {}
impl LayerExt for Http {
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

let mut pb = PacketParser::new();

// Add a layer binding to `Tcp`
// if the current layer is Tcp and the destination port is 80,
// return `Http` as a the next layer to parse
pb.bind_layer(|tcp: &Tcp, _rest| {
    if tcp.dport == 80 {
        Some(Http::parse_layer)
    } else {
        None
    }
});

// Ether / IP / TCP / "GET /example HTTP/1.1"
let test_data = hex!("ffffffffffff0000000000000800450000330001000040067cc27f0000017f00000100140050000000000000000050022000ffa20000474554202f6578616d706c6520485454502f312e31");
let (_rest, packet) = pb.parse_packet::<Ether>(&test_data).unwrap();

let layers = packet.layers();

assert!(is_layer!(layers[0], Ether));
assert!(is_layer!(layers[1], Ipv4));
assert!(is_layer!(layers[2], Tcp));
assert!(is_layer!(layers[3], Http));
```

# Interface

An [Interface](crate::datalink::Interface) provides the circuitry necessary to perform I/O with packets.

This could be reading/writing from/to a network interface, a pcap file, or other.

See [here](crate::datalink) for more information.


## Example

```rust,no_run
use nata::{
    datalink::{pcap::Pcap, Interface, PacketWrite},
    layer::{ether::Ether, ip::Ipv4, raw::Raw, tcp::Tcp, LayerExt, LayerOwned},
    packet::Packet,
};

// Read from interface using libpcap
let int = Interface::init::<Pcap>("lo").unwrap();

let (mut rx, mut _tx) = int.into_split();

for (_i, pkt) in (&mut rx).enumerate() {
    println!("Packet: {:?}", pkt);
}
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

#[cfg(feature = "std")]
pub mod datalink;
