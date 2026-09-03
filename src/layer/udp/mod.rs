/*!
UDP layer
*/

use crate::get_layer;
use crate::layer::ip::{IpProtocol, Ipv4, Ipv6};
use crate::layer::{Layer, LayerError, LayerExt, LayerOwned};
use alloc::{format, string::ToString, vec::Vec};
use core::convert::TryFrom;
use deku::prelude::*;

/**
UDP Header

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Source Port          |       Destination Port        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            Length             |            Checksum           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```
*/
#[derive(Debug, Default, PartialEq, Clone, DekuRead, DekuWrite)]
#[deku(endian = "big")]
pub struct Udp {
    /// Source Port
    pub sport: u16,
    /// Destination Port
    pub dport: u16,
    /// Length of UDP header and payload
    pub length: u16,
    /// Checksum
    pub checksum: u16,
}

/// Ipv6 pseudo header used in udp checksum calculation
#[derive(Debug, PartialEq, Clone, DekuWrite)]
#[deku(endian = "big")]
struct Ipv6PseudoHeader {
    src: u128,
    dst: u128,
    length: u32,
    zeros: [u8; 3],
    next_header: IpProtocol,
}

impl Ipv6PseudoHeader {
    fn new(ipv6: &Ipv6, udp_length: u32) -> Self {
        Ipv6PseudoHeader {
            src: ipv6.src,
            dst: ipv6.dst,
            length: udp_length,
            zeros: [0; 3],
            next_header: ipv6.next_header,
        }
    }
}

/// Ipv4 pseudo header used in udp checksum calculation
#[derive(Debug, PartialEq, Clone, DekuWrite)]
#[deku(endian = "big")]
struct Ipv4PseudoHeader {
    src: u32,
    dst: u32,
    zeros: u8,
    protocol: IpProtocol,
    length: u16,
}

impl Ipv4PseudoHeader {
    fn new(ipv4: &Ipv4, tcp_length: u16) -> Self {
        Ipv4PseudoHeader {
            src: ipv4.src,
            dst: ipv4.dst,
            zeros: 0,
            protocol: ipv4.protocol,
            length: tcp_length,
        }
    }
}

impl Layer for Udp {}
impl LayerExt for Udp {
    fn finalize(&mut self, prev: &[LayerOwned], next: &[LayerOwned]) -> Result<(), LayerError> {
        let udp_header = {
            let mut data = LayerExt::to_bytes(self)?;

            // Clear checksum bytes for calculation
            data[6] = 0x00;
            data[7] = 0x00;

            data
        };
        let udp_header_len = udp_header.len();

        let udp_payload = crate::layer::utils::layers_to_bytes(next)?;

        // length of udp header + udp_payload
        let udp_length = udp_header_len
            .checked_add(udp_payload.len())
            .ok_or_else(|| {
                LayerError::Finalize(
                    "Overflow occured when calculating length for udp (v4) checksum".to_string(),
                )
            })?;

        self.length = u16::try_from(udp_length).map_err(|_e| {
            LayerError::Finalize(format!("Invalid Udp length {} > {}", udp_length, u16::MAX))
        })?;

        // Update the udp checksum
        if let Some(prev_layer) = prev.last() {
            let ip_pseudo_header = if let Some(ipv4) = get_layer!(prev_layer, Ipv4) {
                Some(
                    Ipv4PseudoHeader::new(
                        ipv4,
                        u16::try_from(udp_length).map_err(|_e| {
                            LayerError::Finalize("Failed to convert udp_length to u16".to_string())
                        })?,
                    )
                    .to_bytes()?,
                )
            } else if let Some(ipv6) = get_layer!(prev_layer, Ipv6) {
                Some(
                    Ipv6PseudoHeader::new(
                        ipv6,
                        u32::try_from(udp_length).map_err(|_e| {
                            LayerError::Finalize("Failed to convert udp_length to u32".to_string())
                        })?,
                    )
                    .to_bytes()?,
                )
            } else {
                None
            };

            if let Some(ip_pseudo_header) = ip_pseudo_header {
                let mut data = ip_pseudo_header;
                data.extend(udp_header);
                data.extend(udp_payload);

                self.checksum = super::ip::checksum(&data)
            }
        }

        Ok(())
    }

    fn parse(input: &[u8]) -> Result<(&[u8], Self), LayerError>
    where
        Self: Sized,
    {
        let ((rest, bit_offset), udp) = Udp::from_bytes((input, 0))?;
        debug_assert_eq!(0, bit_offset);
        Ok((rest, udp))
    }

    fn to_bytes(&self) -> Result<Vec<u8>, LayerError> {
        Ok(DekuContainerWrite::to_bytes(self)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layer::ip::{Ipv4, Ipv6};
    use hexlit::hex;
    use rstest::*;
    use std::convert::TryFrom;

    macro_rules! declare_test_layer {
        ($name:ident, $size:tt) => {
            #[derive(Debug, Default, Clone)]
            struct $name {}
            #[allow(dead_code)]
            impl $name {
                fn new() -> Self {
                    Self {}
                }
                fn boxed() -> Box<dyn LayerExt> {
                    Box::new(Self {})
                }
            }
            impl Layer for $name {}
            impl LayerExt for $name {
                fn finalize(
                    &mut self,
                    _prev: &[LayerOwned],
                    _next: &[LayerOwned],
                ) -> Result<(), LayerError> {
                    unimplemented!()
                }

                fn parse(_input: &[u8]) -> Result<(&[u8], Self), LayerError>
                where
                    Self: Sized,
                {
                    unimplemented!()
                }

                fn to_bytes(&self) -> Result<Vec<u8>, LayerError> {
                    Ok([0u8; $size].to_vec())
                }
            }
        };
    }

    declare_test_layer!(Layer0, 0);
    declare_test_layer!(Layer100, 100);

    #[rstest(input, expected,
        case(
            &hex!("ff02ff35002907a9"),
            Udp {
                sport: 65282,
                dport: 65333,
                length: 41,
                checksum: 0x07a9,
            },
        ),
    )]
    fn test_udp_rw(input: &[u8], expected: Udp) {
        let ret_read = Udp::try_from(input).unwrap();
        assert_eq!(expected, ret_read);

        let ret_write = LayerExt::to_bytes(&ret_read).unwrap();
        assert_eq!(input.to_vec(), ret_write);
    }

    #[test]
    fn test_udp_default() {
        assert_eq!(
            Udp {
                sport: 0,
                dport: 0,
                length: 0,
                checksum: 0,
            },
            Udp::default()
        )
    }

    #[test]
    fn test_udp_finalize_checksum_v4() {
        let expected_checksum = 0x0127;

        let ipv4 = Box::new(Ipv4::default());

        let mut udp = Udp::default();

        udp.finalize(
            &[ipv4],
            &[Layer100::boxed(), Layer0::boxed(), Layer100::boxed()],
        )
        .unwrap();

        assert_eq!(expected_checksum, udp.checksum);
    }

    #[test]
    fn test_udp_finalize_checksum_v6() {
        let expected_checksum = 0x00F3;

        let ipv6 = Box::new(Ipv6::default());

        let mut udp = Udp::default();

        udp.finalize(
            &[ipv6],
            &[Layer100::boxed(), Layer0::boxed(), Layer100::boxed()],
        )
        .unwrap();

        assert_eq!(expected_checksum, udp.checksum);
    }

    #[rstest(expected_length, layers,
        case::none(8, &[]),
        case::empty(8, &[Layer0::boxed()]),
        case::empty(108, &[Layer100::boxed()]),
        case::empty(208, &[Layer100::boxed(), Layer0::boxed(), Layer100::boxed()]),
    )]
    fn test_ipv4_finalize_length(expected_length: u16, layers: &[LayerOwned]) {
        let mut udp = Udp::default();

        // Finalize should update the length
        udp.finalize(&[], layers).unwrap();
        assert_ne!(0, udp.length);

        assert_eq!(expected_length, udp.length);
    }

    #[test]
    fn test_udp_finalize() {
        let mut udp = Udp::default();
        assert_eq!(0, udp.checksum);
        assert_eq!(0, udp.length);

        let ipv4 = Box::new(Ipv4::default());
        udp.finalize(&[ipv4], &[Layer100::boxed()]).unwrap();

        // Only these fields should change during a finalize
        let expected_udp = Udp {
            checksum: 0x018B,
            length: 108,
            ..Default::default()
        };

        assert_eq!(expected_udp, udp);
    }
}
