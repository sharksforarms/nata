# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0](https://github.com/sharksforarms/nata/releases/tag/v0.1.0) - 2026-09-04

### Added

- add no_std and WASM fixtures
- add packet construction and I/O examples
- Add Icmp layer
- Add interface metadata
- Allow a `Packet` to be cloned
- Allow non-Ethernet reading from pcap file
- Add PcapFile writing
- Add read and write tests comparing to scapy generated pcap
- Change PcapFile interface to use pcap-file crate
- rename PacketBuilder to PacketParser
- Improve overall documentation
- add UDP layer
- Add some tests for datalink traits
- rename `to_vec` to `to_bytes`
- rename rx and tx to reader and writer
- Add interface splitting
- Add initial packet interface module
- Add a default set of layer bindings
- Pass the `rest` to bind_layer callback
- add benchmarks for layer parsing and writing
- add some cargo-fuzz for the parsing entrypoints
- Add TCP offset calculation and TCP padding
- Implement the Tcp finalize
- Implement Ipv6 finalize
- Implement Ipv4 finalize
- Add `to_vec` method to Layers
- Initial Ether, Ipv4/6 and Tcp parsers
- Remove `LayerBuilder` in favor of Fn
- improve layer binding

### Fixed

- license
- ipv4
- default Ipv4 version and ihl
- remove commented code
- Ipv4 update length before checksum
- typo
- clippy suggestion
- typo/spelling
- expand packet tests
- Add catch-all Unknown type to ether type and ip proto
- add #[non_exhaustive] to enums which may change
- Add layer bindings for IP -> UDP
- UDP finalize length
- Rename data_of_layers to layers_to_bytes
- Break early if all data is consumed
- unread fields
- fix benches
- Use `find` instead of `filter().next()`
- set default-features=false for wasm test
- Only enable datalink for std
- Add feature requirements to example
- Parse a Raw after TCP
- cargo doc warnings, add links to RFCs
- default tcp offset to 5
- check ipv4 checksum and length in test
- file no longer required

### Other

- remove netmap support
- install netmap headers in Docker image
- extend validation and fuzzing helpers
- run push checks on master
- add centered README artwork
- make libpcap support explicit
- align toolchains and feature checks
- add release-plz automation
- rename Hatchet to Nata
- document usage, capabilities, and licensing
- add containerized development workflow
- update dependencies and parsing internals
- Add underconstruction to readme
- Basic README improvements
- Add some examples to library
- update rstest
- add libpcap to build
- Enable pcap feature for coverage
- Remove running of examples
- change name and add README
- Add some initial documentation
- Initial commit
