//! Build with `cargo build --release --target thumbv7em-none-eabihf`.
#![no_std]
#![no_main]

use core::{mem::MaybeUninit, panic::PanicInfo, ptr::addr_of_mut};

use cortex_m as _;
use cortex_m_rt::entry;
use embedded_alloc::LlffHeap as Heap;
use example_no_std::{build_and_inspect_udp, UdpSummary, PAYLOAD};

#[global_allocator]
static HEAP: Heap = Heap::empty();

const HEAP_SIZE: usize = 16 * 1024;
static mut HEAP_MEMORY: [MaybeUninit<u8>; HEAP_SIZE] = [MaybeUninit::uninit(); HEAP_SIZE];

#[entry]
fn main() -> ! {
    // Hatchet's packet representation uses Vec, Box, and HashMap, so a no_std
    // application must provide an allocator before invoking it.
    unsafe {
        HEAP.init(addr_of_mut!(HEAP_MEMORY) as *mut u8 as usize, HEAP_SIZE);
    }

    assert_eq!(
        Some(UdpSummary {
            source_address: 0xc000_0201,
            destination_address: 0xc633_6402,
            source_port: 40_000,
            destination_port: 53,
            payload_length: PAYLOAD.len(),
        }),
        build_and_inspect_udp()
    );

    loop {
        core::hint::spin_loop();
    }
}

#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
