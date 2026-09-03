use deku::prelude::*;

// Size in bytes of a MaxAddress
const MACADDR_SIZE: usize = 6;

/// Type representing an ethernet mac address
#[derive(Debug, PartialEq, Clone, Default, DekuRead, DekuWrite)]
#[deku(
    ctx_default = "deku::ctx::Endian::Big",
    ctx = "_endian: deku::ctx::Endian"
)]
pub struct MacAddress(pub [u8; MACADDR_SIZE]);

#[cfg(test)]
mod tests {
    use super::*;
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
}
