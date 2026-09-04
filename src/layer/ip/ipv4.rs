/*!
  Ipv4
*/
use crate::layer::{Layer, LayerError, LayerExt, LayerOwned};

use super::IpProtocol;
use alloc::{string::ToString, vec, vec::Vec};
use core::convert::TryFrom;
use deku::prelude::*;

/// Ipv4 option class
#[derive(Debug, PartialEq, Clone, DekuRead, DekuWrite)]
#[deku(
    id_type = "u8",
    bits = "2",
    ctx = "endian: deku::ctx::Endian",
    endian = "endian"
)]
#[allow(missing_docs)]
pub enum Ipv4OptionClass {
    #[deku(id = "0")]
    Control,
    #[deku(id = "1")]
    Reserved1,
    #[deku(id = "2")]
    Debug,
    #[deku(id = "3")]
    Reserved2,
}

/// Ipv4 option type
#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, PartialEq, Clone, DekuRead, DekuWrite)]
#[deku(
    id_type = "u8",
    bits = "5",
    ctx = "endian: deku::ctx::Endian",
    endian = "endian"
)]
pub enum Ipv4OptionType {
    /// End of Option List
    #[deku(id = "0")]
    EOOL,
    /// No Operation
    #[deku(id = "1")]
    NOP,
    /// Unknown
    #[deku(id_pat = "_")]
    Unknown {
        /// option type
        type_: u8,
        /// option length
        #[deku(update = "{u8::try_from(
            value.len()
            .checked_add(2)
            .ok_or_else(|| DekuError::Parse(\"overflow when updating ipv4 option length\".into()))?
        )?}")]
        length: u8,
        /// option value
        #[deku(
            count = "length.checked_sub(2).ok_or_else(|| DekuError::Parse(\"overflow when parsing ipv4 option\".into()))?"
        )]
        value: Vec<u8>,
    },
}

/// Ipv4 option
#[derive(Debug, PartialEq, Clone, DekuRead, DekuWrite)]
#[deku(ctx = "endian: deku::ctx::Endian", endian = "endian")]
#[allow(missing_docs)]
pub struct Ipv4Option {
    #[deku(bits = 1)]
    pub copied: u8,
    pub class: Ipv4OptionClass,
    pub option: Ipv4OptionType,
}

/**
Ipv4 Header

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version|  IHL  |    DSCP   |ECN|         Total Length          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Identification        |Flags|      Fragment Offset    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Time to Live |    Protocol   |         Header Checksum       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Source Address                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Destination Address                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Options                    |    Padding    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```
*/
#[derive(Debug, PartialEq, Clone, DekuRead, DekuWrite)]
#[deku(endian = "big")]
pub struct Ipv4 {
    /// Version
    #[deku(bits = "4")]
    pub version: u8,
    /// Internet Header Length
    #[deku(bits = "4")]
    pub ihl: u8,
    /// Differentiated Services Code Point
    #[deku(bits = "6")]
    pub dscp: u8,
    /// Explicit Congestion Notification
    #[deku(bits = "2")]
    pub ecn: u8,
    /// Total Length
    pub length: u16,
    /// Identification
    pub identification: u16,
    /// Flags
    #[deku(bits = "3")]
    pub flags: u8,
    /// Fragment Offset
    #[deku(bits = "13")]
    pub offset: u16,
    /// Time To Live
    pub ttl: u8,
    /// Protocol
    pub protocol: IpProtocol,
    /// Header checksum
    pub checksum: u16,
    /// Source IP Address
    pub src: u32,
    /// Destination IP Address
    pub dst: u32,
    /// List of ipv4 options
    #[deku(bytes_read = "ihl.saturating_sub(5) * 4")]
    pub options: Vec<Ipv4Option>,
}

impl Ipv4 {
    /// Update the checksum field
    pub fn update_checksum(&mut self) -> Result<(), LayerError> {
        let mut ipv4 = LayerExt::to_bytes(self)?;

        // Bytes 10, 11 are the checksum. Clear them and re-calculate.
        ipv4[10] = 0x00;
        ipv4[11] = 0x00;

        self.checksum = super::checksum(&ipv4);

        Ok(())
    }
}

impl Default for Ipv4 {
    fn default() -> Self {
        Ipv4 {
            version: 4,
            ihl: 5,
            ecn: 0,
            dscp: 0,
            length: 0,
            identification: 0,
            flags: 0,
            offset: 0,
            ttl: 0,
            protocol: IpProtocol::default(),
            checksum: 0x0000,
            src: 0x7F000001,
            dst: 0x7F000001,
            options: vec![],
        }
    }
}

impl Layer for Ipv4 {}
impl LayerExt for Ipv4 {
    fn finalize(&mut self, _prev: &[LayerOwned], next: &[LayerOwned]) -> Result<(), LayerError> {
        self.length = u16::try_from(
            self.length()?
                .checked_add(crate::layer::utils::length_of_layers(next)?)
                .ok_or_else(|| {
                    LayerError::Finalize(
                        "Overflow occured when calculating ipv4 length".to_string(),
                    )
                })?,
        )
        .map_err(|_e| LayerError::Finalize("Could not convert layer length to u16".to_string()))?;

        // TODO: Update IHL

        self.update_checksum()?;

        Ok(())
    }

    fn parse(input: &[u8]) -> Result<(&[u8], Self), LayerError>
    where
        Self: Sized,
    {
        let ((rest, bit_offset), ipv4) = Ipv4::from_bytes((input, 0))?;
        debug_assert_eq!(0, bit_offset);
        Ok((rest, ipv4))
    }

    fn to_bytes(&self) -> Result<Vec<u8>, LayerError> {
        Ok(DekuContainerWrite::to_bytes(self)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layer::{Layer, LayerError, LayerExt};
    use alloc::boxed::Box;
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
            &hex!("4500004b0f490000801163a591fea0ed91fd02cb"),
            Ipv4 {
                version: 4,
                ihl: 5,
                ecn: 0,
                dscp: 0,
                length: 75,
                identification: 0x0f49,
                flags: 0,
                offset: 0,
                ttl: 128,
                protocol: IpProtocol::UDP,
                checksum: 0x63a5,
                src: 0x91FEA0ED,
                dst: 0x91FD02CB,
                options: vec![],
            },
        ),

        case::with_option(
            &hex!("4f00007c000040004001fd307f0000017f00000186280000000101220001ae0000000000000000000000000000000000000000000000000000000001"),
            Ipv4 {
                version: 4,
                ihl: 15,
                ecn: 0,
                dscp: 0,
                length: 124,
                identification: 0,
                flags: 2,
                offset: 0,
                ttl: 64,
                protocol: IpProtocol::ICMP,
                checksum: 0xfd30,
                src: 0x7F000001,
                dst: 0x7F000001,
                options: vec![
                    Ipv4Option {
                        copied: 1,
                        class: Ipv4OptionClass::Control,
                        option: Ipv4OptionType::Unknown { type_: 6, length: 40, value: vec![0, 0, 0, 1, 1, 34, 0, 1, 174, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1] }
                    }
                ],
            },
        ),
    )]
    fn test_ipv4_rw(input: &[u8], expected: Ipv4) {
        let ret_read = Ipv4::try_from(input).unwrap();
        assert_eq!(expected, ret_read);

        let ret_write = LayerExt::to_bytes(&ret_read).unwrap();
        assert_eq!(input.to_vec(), ret_write);
    }

    #[test]
    fn test_ipv4_default() {
        assert_eq!(
            Ipv4 {
                version: 4,
                ihl: 5,
                ecn: 0,
                dscp: 0,
                length: 0,
                identification: 0,
                flags: 0,
                offset: 0,
                ttl: 0,
                protocol: IpProtocol::TCP,
                checksum: 0x0000,
                src: 0x7F000001,
                dst: 0x7F000001,
                options: vec![],
            },
            Ipv4::default()
        );
    }

    #[test]
    fn test_ipv4_checksum_update() {
        let expected_checksum = 0x9010;

        let mut ipv4 =
            Ipv4::try_from(hex!("450002070f4540008006 AABB 91fea0ed41d0e4df").as_ref()).unwrap();

        // Update the checksum
        ipv4.update_checksum().unwrap();

        assert_eq!(expected_checksum, ipv4.checksum);
    }

    #[test]
    fn test_ipv4_finalize_checksum() {
        let expected_checksum = 0x9203;

        let mut ipv4 =
            Ipv4::try_from(hex!("450002070f4540008006 AABB 91fea0ed41d0e4df").as_ref()).unwrap();

        // Finalize should update the checksum
        ipv4.finalize(&[], &[]).unwrap();

        assert_eq!(expected_checksum, ipv4.checksum);
    }

    #[rstest(expected_length, layers,
        case::none(20, &[]),
        case::empty(20, &[Layer0::boxed()]),
        case::empty(120, &[Layer100::boxed()]),
        case::empty(220, &[Layer100::boxed(), Layer0::boxed(), Layer100::boxed()]),
    )]
    fn test_ipv4_finalize_length(expected_length: u16, layers: &[LayerOwned]) {
        let mut ipv4 = Ipv4::default();

        // Finalize should update the length
        ipv4.finalize(&[], layers).unwrap();
        assert_ne!(0, ipv4.length);

        assert_eq!(expected_length, ipv4.length);
    }

    #[test]
    fn test_ipv4_finalize() {
        let mut ipv4 = Ipv4::default();
        assert_eq!(0, ipv4.checksum);
        assert_eq!(0, ipv4.length);

        ipv4.finalize(&[Layer100::boxed()], &[Layer100::boxed()])
            .unwrap();

        // Only these fields should change during a finalize
        let expected_ipv4 = Ipv4 {
            checksum: 0xBC7E,
            length: 120,
            ..Default::default()
        };
        assert_eq!(expected_ipv4, ipv4);
    }
}
