/*!
Layer parsing and construction

A layer is a slice of a packet, the protocol definition.

A packet layer is represented by [`PacketLayer`].

Internally, nata uses [deku](https://github.com/sharksforarms/deku) to easily handle the
symmetric serialization and deserialization of layers.
*/
use alloc::{boxed::Box, vec::Vec};
use core::any::Any;

pub mod error;
pub(crate) mod utils;
pub use error::LayerError;

pub mod ether;
pub mod icmp;
pub mod ip;
pub mod raw;
pub mod tcp;
pub mod udp;

#[doc(hidden)]
pub trait AsAny {
    fn as_any(&self) -> &dyn Any;
    fn as_any_mut(&mut self) -> &mut dyn Any;
}

// AsAny is implemented on all `Any` values so `PacketLayer` can support typed
// downcasts.
impl<T: Any> AsAny for T {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

/// A packet layer that can be parsed, finalized, and serialized.
///
/// New layers only need to implement this trait. Because packets are
/// cloneable, implementors must also be `Clone` (or provide a
/// [`LayerClone`] implementation).
pub trait PacketLayer: core::fmt::Debug + AsAny + LayerClone {
    /// Finalize a layer
    ///
    /// Previous and next layers are passed as arguments to update fields in relation to previous
    /// and next layers.
    ///
    /// This can be used to update inter-dependant fields such as
    /// checksums, lengths, etc.
    fn finalize(&mut self, prev: &[LayerOwned], next: &[LayerOwned]) -> Result<(), LayerError>;

    /// Parse a layer from bytes
    ///
    /// Returns the remaining un-parsed data and the layer type
    fn parse(input: &[u8]) -> Result<(&[u8], Self), LayerError>
    where
        Self: Sized;

    /// Parse a layer from bytes
    ///
    /// Returns the remaining un-parsed data and a boxed [`PacketLayer`].
    fn parse_layer(input: &[u8]) -> Result<(&[u8], Box<dyn PacketLayer>), LayerError>
    where
        Self: 'static + Sized,
    {
        Self::parse(input).map(|(rest, layer)| (rest, Box::new(layer) as Box<dyn PacketLayer>))
    }

    /// Serialize the layer to bytes
    fn to_bytes(&self) -> Result<Vec<u8>, LayerError>;

    /// Return a short display name for this layer.
    fn name(&self) -> &'static str {
        core::any::type_name::<Self>()
            .rsplit("::")
            .next()
            .unwrap_or("Layer")
    }

    /// Return the serialized length in bytes of the layer
    ///
    /// This method calls `to_bytes` and returns the length.
    ///
    /// Implement this method if there's a more efficient way of
    /// retrieving the serialized length (for example if it's a static length)
    fn length(&self) -> Result<usize, LayerError> {
        Ok(self.to_bytes()?.len())
    }
}

/// A boxed [`PacketLayer`].
pub type LayerOwned = Box<dyn PacketLayer>;

/// Trait used to make a [`PacketLayer`] cloneable.
pub trait LayerClone {
    /// Clone a layer
    fn clone_box(&self) -> Box<dyn PacketLayer>;
}

impl<T: 'static + PacketLayer + Clone> LayerClone for T {
    fn clone_box(&self) -> Box<dyn PacketLayer> {
        Box::new(self.clone())
    }
}

impl Clone for Box<dyn PacketLayer> {
    fn clone(&self) -> Box<dyn PacketLayer> {
        self.clone_box()
    }
}

/// Convert a concrete layer into the erased representation used by a
/// [`Packet`](crate::packet::Packet).
pub trait IntoLayer {
    /// Convert this value into an owned packet layer.
    fn into_layer(self) -> LayerOwned;
}

impl<T: PacketLayer + 'static> IntoLayer for T {
    fn into_layer(self) -> LayerOwned {
        Box::new(self)
    }
}

impl IntoLayer for LayerOwned {
    fn into_layer(self) -> LayerOwned {
        self
    }
}
