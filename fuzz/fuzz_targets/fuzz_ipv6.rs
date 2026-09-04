#![no_main]
use libfuzzer_sys::fuzz_target;

use nata::layer::{ip::Ipv6, PacketLayer};

fuzz_target!(|data: &[u8]| {
    let _ = Ipv6::parse(data);
});
