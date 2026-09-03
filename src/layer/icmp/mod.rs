/*!
ICMP layer
*/

use crate::layer::{Layer, LayerError, LayerExt, LayerOwned};
use alloc::vec::Vec;
use deku::prelude::*;

mod icmp_type;

pub use icmp_type::IcmpType;

/**
ICMP Header

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      Type     |      Code     |            Checksum           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                            Message                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             Data                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```
*/
#[derive(Debug, PartialEq, Clone, DekuRead, DekuWrite)]
#[deku(endian = "big")]
pub struct Icmp4 {
    /// ICMP Type
    pub icmp_type: IcmpType,
    /// ICMP Subtype
    pub code: u8,
    /// Checksum
    pub checksum: u16,
    /// Message
    pub message: u32,
    /// Data
    #[deku(read_all)]
    pub data: Vec<u8>,
}

impl Default for Icmp4 {
    fn default() -> Self {
        Icmp4 {
            icmp_type: IcmpType::EchoReply,
            code: 0,
            checksum: 0,
            message: 0,
            data: Vec::new(),
        }
    }
}

impl Layer for Icmp4 {}
impl LayerExt for Icmp4 {
    fn finalize(&mut self, _prev: &[LayerOwned], _next: &[LayerOwned]) -> Result<(), LayerError> {
        let icmp_header = {
            let mut data = LayerExt::to_bytes(self)?;

            // Clear checksum bytes for calculation
            data[2] = 0x00;
            data[3] = 0x00;

            data
        };

        self.checksum = super::ip::checksum(&icmp_header);

        Ok(())
    }

    fn parse(input: &[u8]) -> Result<(&[u8], Self), LayerError>
    where
        Self: Sized,
    {
        let ((rest, bit_offset), icmp) = Icmp4::from_bytes((input, 0))?;
        debug_assert_eq!(0, bit_offset);
        Ok((rest, icmp))
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
        case(
            &hex!("0800150d5f560001028e0a6100000000acd90b0000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637"),
            Icmp4 {
                icmp_type: IcmpType::EchoRequest,
                code: 0,
                checksum: 0x150d,
                message: 0x5f560001,
                data: hex!("028e0a6100000000acd90b0000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637").to_vec(),
            },
        ),
    )]
    fn test_icmp_rw(input: &[u8], expected: Icmp4) {
        let ret_read = Icmp4::try_from(input).unwrap();
        assert_eq!(expected, ret_read);

        let ret_write = LayerExt::to_bytes(&ret_read).unwrap();
        assert_eq!(input.to_vec(), ret_write);
    }

    #[test]
    fn test_icmp_default() {
        assert_eq!(
            Icmp4 {
                icmp_type: IcmpType::EchoReply,
                code: 0,
                checksum: 0,
                message: 0,
                data: vec![],
            },
            Icmp4::default()
        )
    }

    #[test]
    fn test_icmp_finalize_checksum() {
        let expected_checksum = 0xFFFF;

        let mut icmp = Icmp4::default();

        icmp.finalize(&[], &[]).unwrap();

        assert_eq!(expected_checksum, icmp.checksum);
    }

    #[test]
    fn test_icmp_finalize() {
        let mut icmp = Icmp4::default();
        assert_eq!(0, icmp.checksum);

        icmp.finalize(&[], &[]).unwrap();

        // Only these fields should change during a finalize
        let expected_icmp = Icmp4 {
            checksum: 0xFFFF,
            ..Default::default()
        };

        assert_eq!(expected_icmp, icmp);
    }
}
