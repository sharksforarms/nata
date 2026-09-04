/*!
  Helper functions relating to layers
*/
use alloc::{string::ToString, vec::Vec};

use crate::layer::{LayerError, LayerOwned};

/// Returns the sum of the length of each layer
pub(crate) fn length_of_layers(layers: &[LayerOwned]) -> Result<usize, LayerError> {
    layers.iter().try_fold(0usize, |acc, layer| {
        let len = layer.length()?;
        acc.checked_add(len).ok_or_else(|| {
            LayerError::Finalize("Overflow occured when calculating ipv4 length field".to_string())
        })
    })
}

/// Returns the data of all layers
pub(crate) fn layers_to_bytes(layers: &[LayerOwned]) -> Result<Vec<u8>, LayerError> {
    layers.iter().try_fold(Vec::new(), |mut acc, layer| {
        let data = layer.to_bytes()?;
        acc.extend(data);
        Ok(acc)
    })
}
