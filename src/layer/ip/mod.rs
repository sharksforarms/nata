/*!
Ipv4 and Ipv6 layer
*/

pub mod ipv4;
pub mod ipv6;
pub mod protocols;

pub use ipv4::Ipv4;
pub use ipv6::Ipv6;
pub use protocols::IpProtocol;

/// 16-bit ip checksum
pub fn checksum(input: &[u8]) -> u16 {
    let mut sum = 0x00;
    let (chunks, remainder) = input.as_chunks::<2>();
    for chunk in chunks {
        sum += u32::from(u16::from_be_bytes(*chunk));
    }

    if let [rem] = remainder {
        sum += u32::from(u16::from_be_bytes([*rem, 0x00]));
    }

    let carry_add = (sum & 0xffff) + (sum >> 16);
    !(((carry_add & 0xffff) + (carry_add >> 16)) as u16)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hexlit::hex;
    use rstest::*;

    #[rstest(input, expected,
        case::calculate(&hex!("45000073000040004011 0000 c0a80001c0a800c7"), 0xB861),
        case::validate(&hex!("45000073000040004011 B861 c0a80001c0a800c7"), 0x0000),

        case::calculate_rem(&hex!("45000073000040004011 0000 c0a80001c0a800c7aa"), 0x0E61),
        case::validate_rem(&hex!("45000073000040004011 0E61 c0a80001c0a800c7aa"), 0x0000),
    )]
    fn test_checksum(input: &[u8], expected: u16) {
        let chksum = checksum(input);
        assert_eq!(expected, chksum);
    }
}
