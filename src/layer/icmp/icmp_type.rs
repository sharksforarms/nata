use deku::prelude::*;

/// Icmp Type
#[derive(Debug, PartialEq, Clone, DekuRead, DekuWrite)]
#[deku(
    id_type = "u8",
    ctx = "endian: deku::ctx::Endian",
    ctx_default = "deku::ctx::Endian::Big",
    endian = "endian"
)]
#[non_exhaustive]
pub enum IcmpType {
    /// Echo Reply
    #[deku(id = "0")]
    EchoReply,
    /// Destination Unreachable
    #[deku(id = "3")]
    DestUnreach,
    /// Source Quench (Deprecated)
    #[deku(id = "4")]
    SourceQuench,
    /// Redirect
    #[deku(id = "5")]
    Redirect,
    /// Alternate Host Address (Deprecated)
    #[deku(id = "6")]
    AlternateHostAddress,
    /// Echo Request
    #[deku(id = "8")]
    EchoRequest,
    /// Router Advertisement
    #[deku(id = "9")]
    RouterAdvertisement,
    /// Router Solicitation
    #[deku(id = "10")]
    RouterSolicitation,
    /// Time Exceeded
    #[deku(id = "11")]
    TimeExceeded,
    /// Parameter Problem
    #[deku(id = "12")]
    ParameterProblem,
    /// Timestamp Request
    #[deku(id = "13")]
    TimestampRequest,
    /// Timestamp Reply
    #[deku(id = "14")]
    TimestampReply,
    /// Information Request (Deprecated)
    #[deku(id = "15")]
    InformationRequest,
    /// Information Reply (Deprecated)
    #[deku(id = "16")]
    InformationReply,
    /// Address Mask Request (Deprecated)
    #[deku(id = "17")]
    AddressMaskRequest,
    #[deku(id = "18")]
    /// Address Mask Reply (Deprecated)
    AddressMaskReply,
    /// Traceroute (Deprecated)
    #[deku(id = "30")]
    Traceroute,
    /// Datagram Conversion Error (Deprecated)
    #[deku(id = "31")]
    DatagramConversionError,
    /// Mobile Host Redirect (Deprecated)
    #[deku(id = "32")]
    MobileHostRedirect,
    /// IPv6 Where-Are-You (Deprecated)
    #[deku(id = "33")]
    Ipv6WhereAreYou,
    /// IPv6 I-Am-Here (Deprecated)
    #[deku(id = "34")]
    Ipv6IAmHere,
    /// Mobile Rehistration Request (Deprecated)
    #[deku(id = "35")]
    MobileRegistrationRequest,
    /// Mobile Rehistration Reply (Deprecated)
    #[deku(id = "36")]
    MobileRegistrationReply,
    /// Domain Name Request (Deprecated)
    #[deku(id = "37")]
    DomainNameRequest,
    /// Domain Name Reply (Deprecated)
    #[deku(id = "38")]
    DomainNameReply,
    /// SKIP (Deprecated)
    #[deku(id = "39")]
    Skip,
    /// Photuris
    #[deku(id = "40")]
    Photuris,
    /// Extended Echo Request
    #[deku(id = "42")]
    ExtendedEchoRequest,
    /// Extended Echo Reply
    #[deku(id = "43")]
    ExtendedEchoReply,

    /// Unknown Icmp Type
    #[deku(id_pat = "_")]
    Unknown(u8),
}
