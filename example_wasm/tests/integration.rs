#![cfg(target_arch = "wasm32")]

extern crate wasm_bindgen_test;
use wasm_bindgen_test::*;

use example_wasm::*;

#[wasm_bindgen_test]
fn test_read_packets() {
    let capture = include_bytes!("../../tests/pcaps/test_pcap_read_write.pcap");
    let output = read_packets(capture).unwrap();

    assert!(output.contains("Packet 1"));
    assert!(output.contains("Parsed 14 packet(s)."));
}
