# Nata on `no_std`

This fixture builds a real `#![no_std]`, `#![no_main]` Cortex-M application.
It initializes an embedded heap, constructs and finalizes an Ethernet/IPv4/UDP
packet, serializes it, parses it back, and inspects its addresses, ports, and
payload length.

Nata's packet representation uses allocation-backed types such as `Vec`,
`Box`, and `HashMap`. A `no_std` application therefore needs an allocator; this
example provides a 16 KiB heap with `embedded-alloc`.

Build it for either target used by CI:

```sh
cargo build --release --target thumbv7em-none-eabihf
cargo build --release --target thumbv6m-none-eabi
```

The firmware is a compile-and-link fixture rather than a board-specific
application. Its `memory.x` contains a generic memory map for link-time
verification and should be replaced with the target board's layout in a real
application. After verifying the packet round trip it spins indefinitely.
