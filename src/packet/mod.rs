/*!
Packet parsing and construction.
*/

use crate::layer::{IntoLayer, LayerOwned, PacketLayer};
use alloc::{boxed::Box, string::String, vec, vec::Vec};
use core::{any::TypeId, fmt, ops::Div};
use hashbrown::HashMap;

mod bindings;

pub mod error;
pub use error::PacketError;

/// A read-only view of an existing packet.
///
/// `PacketRef` borrows the packet's layers and provides the same typed lookup
/// helpers as [`Packet`], without cloning or exposing the layer storage.
#[derive(Clone, Copy)]
pub struct PacketRef<'a> {
    layers: &'a [LayerOwned],
}

impl<'a> PacketRef<'a> {
    /// Create a view borrowed from a packet.
    pub fn from_packet(packet: &'a Packet) -> Self {
        Self {
            layers: &packet.layers,
        }
    }

    /// Return the number of layers in the packet.
    pub fn len(&self) -> usize {
        self.layers.len()
    }

    /// Return whether the packet contains no layers.
    pub fn is_empty(&self) -> bool {
        self.layers.is_empty()
    }

    /// Iterate over the packet's layers.
    pub fn iter(&self) -> impl Iterator<Item = &'a dyn PacketLayer> {
        self.layers.iter().map(|layer| layer.as_ref())
    }

    /// Return the first layer of type `T`.
    pub fn get<T: PacketLayer + 'static>(&self) -> Option<&'a T> {
        self.layers
            .iter()
            .find_map(|layer| layer.as_any().downcast_ref::<T>())
    }

    /// Return all layers of type `T`.
    pub fn get_all<T: PacketLayer + 'static>(&self) -> impl Iterator<Item = &'a T> {
        self.layers
            .iter()
            .filter_map(|layer| layer.as_any().downcast_ref::<T>())
    }

    /// Return whether the packet contains a layer of type `T`.
    pub fn has<T: PacketLayer + 'static>(&self) -> bool {
        self.get::<T>().is_some()
    }

    /// Return a compact, slash-separated layer summary.
    pub fn summary(&self) -> String {
        let mut summary = String::new();
        for (index, layer) in self.iter().enumerate() {
            if index != 0 {
                summary.push_str(" / ");
            }
            summary.push_str(layer.name());
        }
        summary
    }
}

impl<'a> From<&'a Packet> for PacketRef<'a> {
    fn from(packet: &'a Packet) -> Self {
        Self::from_packet(packet)
    }
}

impl fmt::Display for PacketRef<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.summary())
    }
}

/// A packet is an ordered collection of [`PacketLayer`]s.
#[derive(Debug, Default, Clone)]
pub struct Packet {
    layers: Vec<LayerOwned>,
}

impl Packet {
    /// Create an empty packet
    pub fn new() -> Self {
        Self::default()
    }

    /// Start building a packet without exposing its erased layer storage.
    pub fn builder() -> PacketBuilder {
        PacketBuilder::default()
    }

    /// Construct a packet containing one layer.
    pub fn from_layer<L: IntoLayer>(layer: L) -> Self {
        Self {
            layers: vec![layer.into_layer()],
        }
    }

    fn from_boxed_layers(layers: Vec<LayerOwned>) -> Self {
        Self { layers }
    }

    /// Append a layer to the packet.
    pub fn push<L: IntoLayer>(&mut self, layer: L) -> &mut Self {
        self.layers.push(layer.into_layer());
        self
    }

    fn finalize(&mut self) -> Result<(), PacketError> {
        for i in 0..self.layers.len() {
            let (prev, rest) = self.layers.split_at_mut(i);
            let (current, next) = rest.split_at_mut(1);

            let layer = current.first_mut().expect("dev error: should never panic");
            layer.finalize(prev, next)?;
        }

        Ok(())
    }

    /// Borrow this packet through a [`PacketRef`].
    pub fn as_ref(&self) -> PacketRef<'_> {
        PacketRef::from_packet(self)
    }

    /// Iterate over the packet's layers without exposing the backing boxes.
    pub fn iter(&self) -> impl Iterator<Item = &dyn PacketLayer> {
        self.layers.iter().map(|layer| layer.as_ref())
    }

    /// Return the first layer of type `T`.
    pub fn get<T: PacketLayer + 'static>(&self) -> Option<&T> {
        self.layers
            .iter()
            .find_map(|layer| layer.as_any().downcast_ref::<T>())
    }

    /// Return a mutable reference to the first layer of type `T`.
    pub fn get_mut<T: PacketLayer + 'static>(&mut self) -> Option<&mut T> {
        self.layers
            .iter_mut()
            .find_map(|layer| layer.as_any_mut().downcast_mut::<T>())
    }

    /// Return all layers of type `T`.
    pub fn get_all<T: PacketLayer + 'static>(&self) -> impl Iterator<Item = &T> {
        self.layers
            .iter()
            .filter_map(|layer| layer.as_any().downcast_ref::<T>())
    }

    /// Return whether the packet contains a layer of type `T`.
    pub fn has<T: PacketLayer + 'static>(&self) -> bool {
        self.get::<T>().is_some()
    }

    /// Return a compact, slash-separated layer summary.
    pub fn summary(&self) -> String {
        self.as_ref().summary()
    }

    /// Finalize the packet and serialize it to bytes.
    pub fn bytes(&mut self) -> Result<Vec<u8>, PacketError> {
        self.finalize()?;
        self.serialize()
    }

    /// Finalize the packet and serialize it, consuming the packet.
    pub fn into_bytes(mut self) -> Result<Vec<u8>, PacketError> {
        self.bytes()
    }

    fn serialize(&self) -> Result<Vec<u8>, PacketError> {
        Ok(crate::layer::utils::layers_to_bytes(&self.layers)?)
    }
}

impl fmt::Display for Packet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.summary())
    }
}

/// A fluent packet builder.
#[derive(Debug, Default)]
pub struct PacketBuilder {
    packet: Packet,
}

impl PacketBuilder {
    /// Append a layer to the packet being built.
    pub fn layer<L: IntoLayer>(mut self, layer: L) -> Self {
        self.packet.push(layer);
        self
    }

    /// Append a raw payload layer.
    pub fn payload<P: AsRef<[u8]>>(mut self, payload: P) -> Self {
        self.packet
            .push(crate::layer::raw::Raw::new(payload.as_ref()));
        self
    }

    /// Finalize and return the completed packet.
    pub fn build(mut self) -> Result<Packet, PacketError> {
        self.packet.finalize()?;
        Ok(self.packet)
    }
}

/// Convert one layer into a packet so additional layers can be composed with
/// the `/` operator.
pub trait IntoPacket {
    /// Convert this layer into a packet.
    fn into_packet(self) -> Packet;
}

impl<L: IntoLayer> IntoPacket for L {
    fn into_packet(self) -> Packet {
        Packet::from_layer(self)
    }
}

impl<L: IntoLayer> Div<L> for Packet {
    type Output = Packet;

    fn div(mut self, layer: L) -> Self::Output {
        self.push(layer);
        self
    }
}

type LayerBinding = Box<
    dyn Fn(
        &dyn PacketLayer,
        &[u8],
    )
        -> Option<fn(&[u8]) -> Result<(&[u8], Box<dyn PacketLayer>), crate::layer::LayerError>>,
>;

/**
Parse a [Packet] given layer binding rules

A layer binding specifies which [PacketLayer] to read next,
given the current parsed layer and remaining data.

Bindings are executed in reverse order. This allows clients to push new bindings to extend
existing behaviour.
*/
pub struct PacketParser {
    layer_bindings: HashMap<TypeId, Vec<LayerBinding>>,
}

/// Short name for [`PacketParser`].
pub type Parser = PacketParser;

impl PacketParser {
    /// Create a packet parser with default bindings.
    pub fn new() -> Self {
        PacketParser::default()
    }

    /// Create a packet parser without any default bindings
    pub fn without_bindings() -> Self {
        PacketParser {
            layer_bindings: HashMap::new(),
        }
    }

    /// Add a typed, chainable binding from one layer to another.
    ///
    /// The predicate receives the current layer and the remaining input. If
    /// it returns `true`, `To` is parsed next. Bindings added later take
    /// precedence over earlier bindings for the same source layer.
    pub fn bind<From, To>(mut self, predicate: impl 'static + Fn(&From, &[u8]) -> bool) -> Self
    where
        From: PacketLayer + 'static,
        To: PacketLayer + 'static,
    {
        self.bind_layer(move |layer: &From, rest| {
            if predicate(layer, rest) {
                Some(To::parse_layer)
            } else {
                None
            }
        });
        self
    }

    /// Add an advanced dynamic binding to the packet parser.
    ///
    /// The callback receives the current typed layer and remaining input. It
    /// may return any layer parser, which is useful when one source layer can
    /// lead to multiple protocol types. For a fixed destination type, prefer
    /// the chainable [`PacketParser::bind`] API.
    pub fn bind_layer<LayerType: PacketLayer + 'static, F>(&mut self, f: F)
    where
        F: 'static
            + Fn(
                &LayerType,
                &[u8],
            ) -> Option<
                fn(&[u8]) -> Result<(&[u8], Box<dyn PacketLayer>), crate::layer::LayerError>,
            >,
    {
        let tid = TypeId::of::<LayerType>();
        let bindings = self.layer_bindings.entry(tid).or_default();
        (*bindings).push(Box::new(
            move |current_layer: &dyn PacketLayer, rest: &[u8]| -> _ {
                // SAFETY: This callback is only to be called if the layer type is `LayerType` therefor we
                // can safely unwrap here.
                let l = current_layer
                    .as_any()
                    .downcast_ref::<LayerType>()
                    .expect("dev error: This is always Some");
                f(l, rest)
            },
        ));
    }

    /// Parse a complete packet from bytes.
    ///
    /// This is the high-level, strict parsing entry point: it returns an error
    /// if the parser stops before consuming all input. Use
    /// [`PacketParser::parse_partial`] when trailing bytes are expected.
    pub fn parse<T: PacketLayer + 'static>(&self, input: &[u8]) -> Result<Packet, PacketError> {
        let (rest, packet) = self.parse_partial::<T>(input)?;
        if rest.is_empty() {
            Ok(packet)
        } else {
            Err(PacketError::TrailingData(rest.len()))
        }
    }

    /// Parse a packet, returning any unparsed trailing data.
    ///
    pub fn parse_partial<'a, T: PacketLayer + 'static>(
        &self,
        input: &'a [u8],
    ) -> Result<(&'a [u8], Packet), PacketError> {
        let mut layers = vec![];

        let (mut rest, layer) = T::parse(input)?;

        let mut current_layer: Box<dyn PacketLayer> = Box::new(layer);

        // Given the currently parsed layer:
        //  - Lookup the layer bindings for the current layer
        //  - Find the next layer parser by executing the bindings
        //      - bindings are executed in reverse sequence
        //      - if a binding returns a parser, it returns with that parser.
        //        (this is to allow users to override some behaviour)
        //  - Parse the next layer with the parser
        //  - Next layer becomes current layer, loop
        loop {
            if rest.is_empty() {
                break;
            }

            let tid = current_layer.as_any().type_id();
            let callbacks = self.layer_bindings.get(&tid);

            // Using the layer bindings, find the parser for the next layer
            let next_layer_parser = if let Some(callbacks) = callbacks {
                // labelled loop used here to break out early from for loop
                #[allow(clippy::never_loop)]
                'lbl: loop {
                    // start from last inserted
                    for cb in callbacks.iter().rev() {
                        let parser = cb(current_layer.as_ref(), rest);

                        if parser.is_some() {
                            break 'lbl parser;
                        }
                    }

                    break None;
                }
            } else {
                None
            };

            // Next layer becomes the current layer
            if let Some(next_layer_parser) = next_layer_parser {
                let (new_rest, next_layer) = next_layer_parser(rest)?;
                rest = new_rest;

                layers.push(current_layer);
                current_layer = next_layer;
            } else {
                break;
            }
        }

        layers.push(current_layer);

        Ok((rest, Packet::from_boxed_layers(layers)))
    }
}

impl Default for PacketParser {
    fn default() -> Self {
        bindings::create_packetparser()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layer::{LayerError, PacketLayer};

    macro_rules! declare_test_layer {
        ($name:ident, $bytes:tt) => {
            #[derive(Debug, Clone)]
            struct $name {}
            #[allow(dead_code)]
            impl $name {
                fn new() -> Self {
                    Self {}
                }
            }
            impl PacketLayer for $name {
                fn finalize(
                    &mut self,
                    _prev: &[LayerOwned],
                    _next: &[LayerOwned],
                ) -> Result<(), LayerError> {
                    Ok(())
                }

                fn parse(input: &[u8]) -> Result<(&[u8], Self), LayerError>
                where
                    Self: Sized,
                {
                    let (val, rest) = input.split_at($bytes.len());
                    assert_eq!(val, $bytes);
                    Ok((rest, Self {}))
                }

                fn to_bytes(&self) -> Result<Vec<u8>, LayerError> {
                    Ok($bytes.to_vec())
                }
            }
        };
    }

    declare_test_layer!(Layer0, b"layer0");
    declare_test_layer!(Layer1, b"layer1");
    declare_test_layer!(Layer2, b"layer2");

    #[test]
    fn test_packet_owned_layers() {
        let mut packet = Packet::from_layer(Layer0::new());
        packet.push(Layer1::new());
        assert_eq!(2, packet.as_ref().len());
    }

    #[test]
    fn test_packet_bytes() {
        let layer0 = Box::new(Layer0::new());
        let layer1 = Box::new(Layer1::new());
        let layer2 = Box::new(Layer2::new());

        let layers: Vec<LayerOwned> = vec![layer0, layer1, layer2];
        let packet = Packet::from_boxed_layers(layers);
        assert_eq!(b"layer0layer1layer2".to_vec(), packet.into_bytes().unwrap());
    }

    #[test]
    fn test_packet_finalize_lengths() {
        // test a range on lengths for the packet finalize function
        for i in 0..5 {
            let layers: Vec<LayerOwned> = (0..i)
                .map(|_| Box::new(Layer0::new()) as LayerOwned)
                .collect();
            let mut packet = Packet::from_boxed_layers(layers);
            packet.finalize().unwrap();
        }
    }

    #[test]
    fn test_packet_finalize() {
        #[derive(Debug, PartialEq, Clone)]
        struct TestLayer {
            count: u8,                // count increases every time the layer is finalized
            expected_num_prev: usize, // expected number of previous layers when finalized is called
            expected_num_next: usize, // expected number of next layers when finalized is called
        }

        impl TestLayer {
            fn new(expected_num_prev: usize, expected_num_next: usize) -> Self {
                Self {
                    count: 0,
                    expected_num_prev,
                    expected_num_next,
                }
            }
        }

        impl PacketLayer for TestLayer {
            fn finalize(
                &mut self,
                prev: &[LayerOwned],
                next: &[LayerOwned],
            ) -> Result<(), LayerError> {
                assert_eq!(self.expected_num_prev, prev.len());
                assert_eq!(self.expected_num_next, next.len());
                self.count += 1;
                Ok(())
            }

            fn parse(_input: &[u8]) -> Result<(&[u8], Self), LayerError>
            where
                Self: Sized,
            {
                unimplemented!()
            }

            fn to_bytes(&self) -> Result<Vec<u8>, LayerError> {
                unimplemented!()
            }
        }

        let layers: Vec<LayerOwned> = vec![
            Box::new(TestLayer::new(0, 2)),
            Box::new(TestLayer::new(1, 1)),
            Box::new(TestLayer::new(2, 0)),
        ];
        let mut packet = Packet::from_boxed_layers(layers);
        packet.finalize().unwrap();

        // Get layers back as `TestLayer`
        let test_layers: Vec<_> = packet.get_all::<TestLayer>().collect();

        assert_eq!(3, test_layers.len());
        for layer in test_layers {
            assert_eq!(1, layer.count);
        }
    }

    #[test]
    fn test_packet_parser_bind_layer() {
        let mut pb = PacketParser::without_bindings();
        assert_eq!(0, pb.layer_bindings.len());

        pb.bind_layer(|_from: &Layer0, _rest| Some(Layer1::parse_layer));
        assert_eq!(1, pb.layer_bindings.len());
        assert_eq!(
            1,
            pb.layer_bindings
                .get(&TypeId::of::<Layer0>())
                .unwrap()
                .len()
        );

        pb.bind_layer(|_from: &Layer0, _rest| Some(Layer1::parse_layer));
        assert_eq!(1, pb.layer_bindings.len());
        assert_eq!(
            2,
            pb.layer_bindings
                .get(&TypeId::of::<Layer0>())
                .unwrap()
                .len()
        );
    }

    #[test]
    fn test_packet_parser_bind_layer_rest() {
        let mut pb = PacketParser::without_bindings();
        assert_eq!(0, pb.layer_bindings.len());

        pb.bind_layer(|_from: &Layer0, rest| {
            assert_eq!(8, rest.len());
            Some(Layer1::parse_layer)
        });

        assert_eq!(1, pb.layer_bindings.len());

        pb.parse_partial::<Layer0>(b"layer0").unwrap();
    }

    #[test]
    fn test_packet_parser_none() {
        let mut pb = PacketParser::without_bindings();
        assert_eq!(0, pb.layer_bindings.len());

        {
            pb.bind_layer(|_from: &Layer0, _rest| None);

            let (rest, packet) = pb.parse_partial::<Layer0>(b"layer0").unwrap();
            let mut layers = packet.as_ref().iter();
            assert!(rest.is_empty());
            assert!(layers.next().unwrap().as_any().is::<Layer0>());
            assert!(layers.next().is_none());
        }

        {
            pb.bind_layer(|_from: &Layer0, _rest| Some(Layer1::parse_layer));

            let (rest, packet) = pb.parse_partial::<Layer0>(b"layer0layer1").unwrap();
            let mut layers = packet.as_ref().iter();
            assert!(rest.is_empty());
            assert!(layers.next().unwrap().as_any().is::<Layer0>());
            assert!(layers.next().unwrap().as_any().is::<Layer1>());
            assert!(layers.next().is_none());
        }
    }

    #[test]
    fn test_packet_binding_order() {
        let mut pb = PacketParser::without_bindings();
        assert_eq!(0, pb.layer_bindings.len());

        {
            pb.bind_layer(|_from: &Layer0, _rest| Some(Layer1::parse_layer));

            let (rest, packet) = pb.parse_partial::<Layer0>(b"layer0layer1").unwrap();
            let mut layers = packet.as_ref().iter();
            assert!(rest.is_empty());
            assert!(layers.next().unwrap().as_any().is::<Layer0>());
            assert!(layers.next().unwrap().as_any().is::<Layer1>());
            assert!(layers.next().is_none());
        }

        {
            pb.bind_layer(|_from: &Layer0, _rest| Some(Layer2::parse_layer));

            let (rest, packet) = pb.parse_partial::<Layer0>(b"layer0layer2").unwrap();
            let mut layers = packet.as_ref().iter();
            assert!(rest.is_empty());
            assert!(layers.next().unwrap().as_any().is::<Layer0>());
            assert!(layers.next().unwrap().as_any().is::<Layer2>());
            assert!(layers.next().is_none());
        }
    }

    #[test]
    fn test_packet_builder_and_typed_access() {
        use crate::layer::{
            ether::{Ether, MacAddress},
            ip::{IpProtocol, Ipv4},
            raw::Raw,
            udp::Udp,
        };
        use core::net::Ipv4Addr;

        let mut packet = Packet::builder()
            .layer(Ether::new(
                MacAddress::new([0x02, 0, 0, 0, 0, 1]),
                MacAddress::new([0x02, 0, 0, 0, 0, 2]),
            ))
            .layer(
                Ipv4::new(Ipv4Addr::new(192, 0, 2, 1), Ipv4Addr::new(198, 51, 100, 2))
                    .protocol(IpProtocol::UDP),
            )
            .layer(Udp::new(40_000, 53))
            .payload(b"hello")
            .build()
            .unwrap();

        assert!(packet.has::<Ether>());
        assert_eq!(40_000, packet.get::<Udp>().unwrap().sport);
        assert_eq!(b"hello", packet.get::<Raw>().unwrap().payload());

        packet.get_mut::<Ipv4>().unwrap().ttl = 42;
        assert_eq!(42, packet.get::<Ipv4>().unwrap().ttl);

        let packet_ref = packet.as_ref();
        assert_eq!(4, packet_ref.len());
        assert!(packet_ref.has::<Raw>());
        assert_eq!("Ether / Ipv4 / Udp / Raw", packet_ref.summary());

        let bytes = packet.bytes().unwrap();
        let parsed = PacketParser::new()
            .parse::<crate::layer::ether::Ether>(&bytes)
            .unwrap();
        assert_eq!(b"hello", parsed.get::<Raw>().unwrap().payload());
    }

    #[test]
    fn test_packet_slash_composition() {
        use crate::layer::{
            ether::{Ether, MacAddress},
            ip::Ipv4,
            raw::Raw,
            udp::Udp,
        };
        use core::net::Ipv4Addr;

        let mut packet = Ether::new(MacAddress::default(), MacAddress::default()).into_packet()
            / Ipv4::new(Ipv4Addr::new(192, 0, 2, 1), Ipv4Addr::new(198, 51, 100, 2))
            / Udp::new(1, 2)
            / Raw::new(b"payload");

        assert_eq!("Ether / Ipv4 / Udp / Raw", packet.summary());
        assert!(!packet.bytes().unwrap().is_empty());
    }

    #[test]
    fn test_parser_typed_binding_and_strict_parse() {
        let parser = PacketParser::without_bindings().bind::<Layer0, Layer1>(|_, _| true);
        let packet = parser.parse::<Layer0>(b"layer0layer1").unwrap();
        assert_eq!("Layer0 / Layer1", packet.summary());

        let error = PacketParser::without_bindings()
            .parse::<Layer0>(b"layer0tail")
            .unwrap_err();
        assert_eq!(PacketError::TrailingData(4), error);
    }
}
