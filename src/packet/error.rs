/*!
  Packet error
*/
use crate::layer::LayerError;

/// Error parsing or generating a packet
#[derive(Debug, PartialEq)]
#[non_exhaustive]
pub enum PacketError {
    /// Recoverable error containing the amount of bytes required to continue parsing
    Incomplete(usize),
    /// Error parsing a layer
    LayerError(LayerError),
    /// Strict parsing found trailing bytes after the parsed packet
    TrailingData(usize),
}

impl From<LayerError> for PacketError {
    fn from(err: LayerError) -> Self {
        match err {
            LayerError::Incomplete(size) => PacketError::Incomplete(size),
            _ => PacketError::LayerError(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::*;

    #[test]
    fn test_from() {
        let layer_error = LayerError::Incomplete(8);
        let packet_error = PacketError::from(layer_error);
        assert_eq!(PacketError::Incomplete(8), packet_error);

        let layer_error = LayerError::Parse("some error".to_string());
        let packet_error = PacketError::from(layer_error.clone());
        assert_eq!(PacketError::LayerError(layer_error), packet_error);
    }
}
