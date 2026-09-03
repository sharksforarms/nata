#![no_main]
use libfuzzer_sys::fuzz_target;

use nata::layer::{tcp::Tcp, LayerExt};

fuzz_target!(|data: &[u8]| {
    let _ = Tcp::parse(data);
});
