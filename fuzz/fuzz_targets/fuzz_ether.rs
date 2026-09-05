#![no_main]
use libfuzzer_sys::fuzz_target;

use nata::layer::{ether::Ether, PacketLayer};

fuzz_target!(|data: &[u8]| {
    let _ = Ether::parse(data);
});
