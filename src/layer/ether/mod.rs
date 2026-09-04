/*! Ethernet
*/

/*!
Ethernet layer
*/

use crate::layer::PacketLayer;
use alloc::vec::Vec;
use deku::prelude::*;

mod ethertype;
mod macaddress;

pub use ethertype::EtherType;
pub use macaddress::MacAddress;

use super::{LayerError, LayerOwned};

/**
Ethernet Frame Header

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Destination Address                      |
+                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                               |                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
|                         Source Address                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           EtherType           |                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
|                                                               |
+                             Payload                           +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```
*/
#[derive(Debug, PartialEq, Clone, Default, DekuRead, DekuWrite)]
#[deku(endian = "big")]
pub struct Ether {
    /// Destination mac address
    pub dst: MacAddress,

    /// Source mac address
    pub src: MacAddress,

    /// Protocl type of the payload
    pub ether_type: EtherType,
}

impl Ether {
    /// Construct an Ethernet II header for an IPv4 payload.
    ///
    /// The arguments are ordered as source address, destination address to
    /// match the usual packet-building call pattern.
    pub fn new(src: MacAddress, dst: MacAddress) -> Self {
        Self {
            src,
            dst,
            ether_type: EtherType::IPv4,
        }
    }

    /// Set the source MAC address.
    pub fn src(mut self, src: MacAddress) -> Self {
        self.src = src;
        self
    }

    /// Set the destination MAC address.
    pub fn dst(mut self, dst: MacAddress) -> Self {
        self.dst = dst;
        self
    }

    /// Set the Ethernet payload type.
    pub fn ether_type(mut self, ether_type: EtherType) -> Self {
        self.ether_type = ether_type;
        self
    }
}

impl PacketLayer for Ether {
    fn finalize(&mut self, _prev: &[LayerOwned], _next: &[LayerOwned]) -> Result<(), LayerError> {
        // TODO: Maybe update the type based on the next layer?
        Ok(())
    }

    fn parse(input: &[u8]) -> Result<(&[u8], Self), LayerError>
    where
        Self: Sized,
    {
        let ((rest, bit_offset), ether) = Ether::from_bytes((input, 0))?;
        debug_assert_eq!(0, bit_offset);
        Ok((rest, ether))
    }

    fn to_bytes(&self) -> Result<Vec<u8>, LayerError> {
        Ok(DekuContainerWrite::to_bytes(self)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hexlit::hex;
    use rstest::*;
    use std::convert::TryFrom;

    #[rstest(input, expected,
        case(&hex!("feff200001000000010000000800"), Ether {
            dst: MacAddress([0xfe, 0xff, 0x20, 0x00, 0x01, 0x00]),
            src: MacAddress([0x00, 0x00, 0x01, 0x00, 0x00, 0x00]),
            ether_type: EtherType::IPv4,
        }),
    )]
    fn test_ether_rw(input: &[u8], expected: Ether) {
        let ret_read = Ether::try_from(input).unwrap();
        assert_eq!(expected, ret_read);

        let ret_write = PacketLayer::to_bytes(&ret_read).unwrap();
        assert_eq!(input.to_vec(), ret_write);
    }

    #[test]
    fn test_ether_default() {
        assert_eq!(
            Ether {
                dst: MacAddress([0x00u8; 6]),
                src: MacAddress([0x00u8; 6]),
                ether_type: EtherType::IPv4,
            },
            Ether::default()
        )
    }
}
