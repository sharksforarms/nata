use core::{fmt, str::FromStr};
use deku::prelude::*;

// Size in bytes of a MacAddress
const MACADDR_SIZE: usize = 6;

/// Type representing an ethernet mac address
#[derive(Debug, PartialEq, Clone, Default, DekuRead, DekuWrite)]
#[deku(
    ctx_default = "deku::ctx::Endian::Big",
    ctx = "_endian: deku::ctx::Endian"
)]
pub struct MacAddress(pub [u8; MACADDR_SIZE]);

/// Error returned when a MAC address cannot be parsed from text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MacAddressParseError;

impl fmt::Display for MacAddressParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid MAC address; expected six hexadecimal octets")
    }
}

impl MacAddress {
    /// Construct a MAC address from its six octets.
    pub const fn new(octets: [u8; MACADDR_SIZE]) -> Self {
        Self(octets)
    }

    /// Return the address as six octets.
    pub const fn octets(&self) -> [u8; MACADDR_SIZE] {
        self.0
    }
}

impl From<[u8; MACADDR_SIZE]> for MacAddress {
    fn from(octets: [u8; MACADDR_SIZE]) -> Self {
        Self::new(octets)
    }
}

impl AsRef<[u8]> for MacAddress {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl FromStr for MacAddress {
    type Err = MacAddressParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let mut octets = [0u8; MACADDR_SIZE];
        let mut pieces = value.split(':');

        for octet in &mut octets {
            let piece = pieces.next().ok_or(MacAddressParseError)?;
            if piece.is_empty() || piece.len() > 2 {
                return Err(MacAddressParseError);
            }
            *octet = u8::from_str_radix(piece, 16).map_err(|_| MacAddressParseError)?;
        }

        if pieces.next().is_some() {
            return Err(MacAddressParseError);
        }

        Ok(Self::new(octets))
    }
}

impl fmt::Display for MacAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    use rstest::*;

    #[rstest(input, expected,
        case(&[0xAA, 0xFF, 0xFF, 0xFF, 0xFF, 0xBB], MacAddress([0xAA, 0xFF, 0xFF, 0xFF, 0xFF, 0xBB])),
    )]
    fn test_macaddress_rw(input: &[u8], expected: MacAddress) {
        let (_rest, ret_read) = MacAddress::from_bytes((input, 0)).unwrap();
        assert_eq!(expected, ret_read);

        let ret_write = ret_read.to_bytes().unwrap();
        assert_eq!(input.to_vec(), ret_write);
    }

    #[test]
    fn test_macaddress_default() {
        assert_eq!(MacAddress([0x00u8; 6]), MacAddress::default())
    }

    #[test]
    fn test_macaddress_text() {
        let address = "02:00:00:00:00:01".parse::<MacAddress>().unwrap();
        assert_eq!(MacAddress::new([2, 0, 0, 0, 0, 1]), address);
        assert_eq!("02:00:00:00:00:01", address.to_string());
        assert!("02:00:00:00:00".parse::<MacAddress>().is_err());
    }
}
