/*!
Packet parsing and construction.
*/

use crate::{
    get_layer,
    layer::{LayerExt, LayerOwned, LayerRef},
};
use alloc::{boxed::Box, vec, vec::Vec};
use core::any::TypeId;
use hashbrown::HashMap;

pub mod bindings;

pub mod error;
pub use error::PacketError;

/// Read-only view of a packet
pub struct PacketView<'a> {
    #[allow(dead_code)]
    layers: Vec<LayerRef<'a>>,
}

impl<'a> PacketView<'a> {
    /// Create a PacketView from layers
    pub fn from_layers(layers: Vec<LayerRef<'a>>) -> Self {
        Self { layers }
    }
}

/// A packet is simply a collection of [Layer](crate::layer::LayerExt)
#[derive(Debug, Default, Clone)]
pub struct Packet {
    layers: Vec<LayerOwned>,
}

impl Packet {
    /// Create an empty packet
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct a Packet given existing layers
    pub fn from_layers(layers: Vec<LayerOwned>) -> Self {
        Self { layers }
    }

    /// Finalize a packet
    ///
    /// This will call finalize on each layer of the packet
    pub fn finalize(&mut self) -> Result<(), PacketError> {
        for i in 0..self.layers.len() {
            let (prev, rest) = self.layers.split_at_mut(i);
            let (current, next) = rest.split_at_mut(1);

            let layer = current.first_mut().expect("dev error: should never panic");
            layer.finalize(prev, next)?;
        }

        Ok(())
    }

    /// Immutable access of the layers
    pub fn layers(&self) -> &[LayerOwned] {
        &self.layers
    }

    /// Mutable access of the layers
    pub fn layers_mut(&mut self) -> &mut [LayerOwned] {
        &mut self.layers
    }

    /// Packet to bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>, PacketError> {
        Ok(crate::layer::utils::layers_to_bytes(&self.layers)?)
    }
}

type LayerBinding = Box<
    dyn Fn(
        &dyn LayerExt,
        &[u8],
    )
        -> Option<fn(&[u8]) -> Result<(&[u8], Box<dyn LayerExt>), crate::layer::LayerError>>,
>;

/**
Parse a [Packet](self::Packet) given layer binding rules

A layer binding specifies which [Layer](crate::layer::Layer) to read next,
given the current parsed layer and remaining data.

Bindings are executed in reverse order. This allows clients to push new bindings to extend
existing behaviour.
*/
pub struct PacketParser {
    layer_bindings: HashMap<TypeId, Vec<LayerBinding>>,
}

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

    /**
    Add a layer binding to the packet parser

    This allows the definition of custom logic to help the parser determine the
    next layer.

    # Example

    ```rust
    # use nata::{
    #   is_layer, get_layer,
    #   packet::PacketParser,
    #   layer::{Layer, LayerExt, LayerOwned, LayerError}
    # };
    # #[derive(Debug, PartialEq, Clone)]
    # enum EtherType {
    #    Ipv4 = 0x0800
    # }
    # #[derive(Debug, Clone)]
    # struct Ether {
    #    ether_type: EtherType
    # }
    # impl Layer for Ether {}
    # impl LayerExt for Ether {
    #     fn finalize(&mut self, prev: &[LayerOwned], _next: &[LayerOwned]) -> Result<(), LayerError> {
    #         unimplemented!();
    #     }
    #
    #     fn parse(input: &[u8]) -> Result<(&[u8], Self), LayerError>
    #     where
    #         Self: Sized,
    #     {
    #         Ok((input, Ether { ether_type: EtherType::Ipv4 }))
    #     }
    #
    #     fn to_bytes(&self) -> Result<Vec<u8>, LayerError> {
    #         unimplemented!()
    #     }
    # }
    # impl Layer for Ipv4 {}
    # impl LayerExt for Ipv4 {
    #     fn finalize(&mut self, prev: &[LayerOwned], _next: &[LayerOwned]) -> Result<(), LayerError> {
    #         unimplemented!();
    #     }
    #
    #     fn parse(input: &[u8]) -> Result<(&[u8], Self), LayerError>
    #     where
    #         Self: Sized,
    #     {
    #         Ok((input, Ipv4 {}))
    #     }
    #
    #     fn to_bytes(&self) -> Result<Vec<u8>, LayerError> {
    #         unimplemented!()
    #     }
    # }
    # #[derive(Debug, Clone)]
    # struct Ipv4 {}
    # fn main() {
        let mut packet_parser = PacketParser::without_bindings();

        packet_parser.bind_layer(|ether: &Ether, _rest| {
            match ether.ether_type {
                EtherType::Ipv4 => Some(Ipv4::parse_layer),
                // ...
                _ => None
            }
        });

    #   let input = b"input";
        let (rest, packet) = packet_parser.parse_packet::<Ether>(input).unwrap();

        let layers = packet.layers();
        assert_eq!(2, layers.len());
        assert!(is_layer!(layers[0], Ether));
        assert!(is_layer!(layers[1], Ipv4));
    # }
    ```
    */
    pub fn bind_layer<LayerType: LayerExt + 'static, F>(&mut self, f: F)
    where
        F: 'static
            + Fn(
                &LayerType,
                &[u8],
            )
                -> Option<fn(&[u8]) -> Result<(&[u8], Box<dyn LayerExt>), crate::layer::LayerError>>,
    {
        let tid = TypeId::of::<LayerType>();
        let bindings = self.layer_bindings.entry(tid).or_default();
        (*bindings).push(Box::new(
            move |current_layer: &dyn LayerExt, rest: &[u8]| -> _ {
                // SAFETY: This callback is only to be called if the layer type is `LayerType` therefor we
                // can safely unwrap here.
                let l =
                    get_layer!(current_layer, LayerType).expect("dev error: This is always Some");
                f(l, rest)
            },
        ));
    }

    /// Parse a packet from bytes, returning the un-parsed data
    pub fn parse_packet<'a, T: LayerExt + 'static>(
        &self,
        input: &'a [u8],
    ) -> Result<(&'a [u8], Packet), PacketError> {
        let mut layers = vec![];

        let (mut rest, layer) = T::parse(input)?;

        let mut current_layer: Box<dyn LayerExt> = Box::new(layer);

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

        Ok((rest, Packet::from_layers(layers)))
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
    use crate::{
        get_layer,
        layer::{Layer, LayerError, LayerExt},
    };

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
            impl Layer for $name {}
            impl LayerExt for $name {
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
    fn test_packet_view_from_layers() {
        let layer0 = Layer0::new();
        let layer1 = Layer1::new();

        let layers: Vec<LayerRef> = vec![&layer0, &layer1];
        let packet = PacketView::from_layers(layers);
        assert_eq!(2, packet.layers.len());
    }

    #[test]
    fn test_packet_owned_from_layers() {
        let layer0 = Box::new(Layer0::new());
        let layer1 = Box::new(Layer1::new());

        let layers: Vec<LayerOwned> = vec![layer0, layer1];
        let mut packet = Packet::from_layers(layers);
        assert_eq!(2, packet.layers().len());
        assert_eq!(2, packet.layers_mut().len());
    }

    #[test]
    fn test_packet_to_bytes() {
        let layer0 = Box::new(Layer0::new());
        let layer1 = Box::new(Layer1::new());
        let layer2 = Box::new(Layer2::new());

        let layers: Vec<LayerOwned> = vec![layer0, layer1, layer2];
        let packet = Packet::from_layers(layers);
        assert_eq!(b"layer0layer1layer2".to_vec(), packet.to_bytes().unwrap());
    }

    #[test]
    fn test_packet_finalize_lengths() {
        // test a range on lengths for the packet finalize function
        for i in 0..5 {
            let layers: Vec<LayerOwned> = (0..i)
                .map(|_| Box::new(Layer0::new()) as LayerOwned)
                .collect();
            let mut packet = Packet::from_layers(layers);
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

        impl Layer for TestLayer {}
        impl LayerExt for TestLayer {
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
        let mut packet = Packet::from_layers(layers);
        packet.finalize().unwrap();

        // Get layers back as `TestLayer`
        let test_layers: Vec<_> = packet
            .layers
            .iter()
            .map(|v| get_layer!(v, TestLayer).unwrap())
            .collect();

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

        pb.parse_packet::<Layer0>(b"layer0").unwrap();
    }

    #[test]
    fn test_packet_parser_none() {
        let mut pb = PacketParser::without_bindings();
        assert_eq!(0, pb.layer_bindings.len());

        {
            pb.bind_layer(|_from: &Layer0, _rest| None);

            let (rest, packet) = pb.parse_packet::<Layer0>(b"layer0").unwrap();
            assert_eq!(1, packet.layers.len());
            assert!(rest.is_empty());
            assert!(get_layer!(packet.layers[0], Layer0).is_some());
        }

        {
            pb.bind_layer(|_from: &Layer0, _rest| Some(Layer1::parse_layer));

            let (rest, packet) = pb.parse_packet::<Layer0>(b"layer0layer1").unwrap();
            assert_eq!(2, packet.layers.len());
            assert!(rest.is_empty());
            assert!(get_layer!(packet.layers[0], Layer0).is_some());
            assert!(get_layer!(packet.layers[1], Layer1).is_some());
        }
    }

    #[test]
    fn test_packet_parse_packet_binding_order() {
        let mut pb = PacketParser::without_bindings();
        assert_eq!(0, pb.layer_bindings.len());

        {
            pb.bind_layer(|_from: &Layer0, _rest| Some(Layer1::parse_layer));

            let (rest, packet) = pb.parse_packet::<Layer0>(b"layer0layer1").unwrap();
            assert_eq!(2, packet.layers.len());
            assert!(rest.is_empty());
            assert!(get_layer!(packet.layers[0], Layer0).is_some());
            assert!(get_layer!(packet.layers[1], Layer1).is_some());
        }

        {
            pb.bind_layer(|_from: &Layer0, _rest| Some(Layer2::parse_layer));

            let (rest, packet) = pb.parse_packet::<Layer0>(b"layer0layer2").unwrap();
            assert_eq!(2, packet.layers.len());
            assert!(rest.is_empty());
            assert!(get_layer!(packet.layers[0], Layer0).is_some());
            assert!(get_layer!(packet.layers[1], Layer2).is_some());
        }
    }
}
