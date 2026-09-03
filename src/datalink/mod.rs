/*!
Read and Write packets over an interface

# Interface Types

Some interface types are enabled via crate features.

| Type | Feature | Description
|-----------|------------------|------------
| [Pnet] | default | Use [libpnet] cross-platform abstraction over a network interface
| [Pnet] | netmap | Enable [netmap] feature in libpnet to utilize netmap for I/O
| [Pcap] | libpcap | Use libpcap for I/O on a network interface

[Pnet]: crate::datalink::pnet::Pnet
[Pcap]: crate::datalink::pcap::Pcap
[libpnet]: https://github.com/libpnet/libpnet
[netmap]: http://info.iet.unipi.it/~luigi/netmap/

# Example

```rust,ignore
let interface = Interface::init::<Pnet>("lo").unwrap();

let (mut rx, mut tx) = int.into_split();

for (_i, pkt) in (&mut rx).enumerate() {
println!("Packet: {:?}", pkt);
}
```
*/

#[cfg(feature = "libpcap")]
pub mod pcap;

#[cfg(feature = "std")]
pub mod pcapfile;

#[cfg(feature = "pnet")]
pub mod pnet;

pub mod error;

use crate::datalink::error::DataLinkError;
use crate::layer::ether::MacAddress;
use crate::packet::{Packet, PacketParser};

/// A generic Packet interface used to Read and Write packets
pub struct Interface<R: PacketRead, W: PacketWrite> {
    reader: R,
    writer: W,
    metadata: InterfaceMetadata,
}

#[derive(Default, Clone)]
struct InterfaceMetadata {
    mac_address: Option<MacAddress>,
}

impl<R: PacketRead, W: PacketWrite> Interface<R, W> {
    /// Initialize read/write interface
    pub fn init<T: PacketInterface<Reader = R, Writer = W>>(
        name: &str,
    ) -> Result<Interface<T::Reader, T::Writer>, DataLinkError>
    where
        Self: Sized,
    {
        T::init(name)
    }

    /// Initialize read/write interface with a custom parser
    pub fn init_with_parser<T: PacketInterface>(
        name: &str,
        packet_parser: PacketParser,
    ) -> Result<Interface<T::Reader, T::Writer>, DataLinkError>
    where
        Self: Sized,
    {
        T::init_with_parser(name, packet_parser)
    }

    /// Split interface into referenced read and write interfaces
    pub fn split(&mut self) -> (InterfaceReaderRef<'_, R>, InterfaceWriterRef<'_, W>) {
        (
            InterfaceReaderRef {
                reader: &mut self.reader,
                metadata: &self.metadata,
            },
            InterfaceWriterRef {
                writer: &mut self.writer,
                metadata: &self.metadata,
            },
        )
    }

    /// Split interface into owned read and write interfaces
    pub fn into_split(self) -> (InterfaceReader<R>, InterfaceWriter<W>) {
        (
            InterfaceReader {
                reader: self.reader,
                metadata: self.metadata.clone(),
            },
            InterfaceWriter {
                writer: self.writer,
                metadata: self.metadata,
            },
        )
    }

    /// Get the mac address of the interface
    pub fn mac_address(&self) -> Option<&MacAddress> {
        self.metadata.mac_address.as_ref()
    }
}

impl<R: PacketRead, W: PacketWrite> PacketWrite for Interface<R, W> {
    fn write(&mut self, packet: Packet) -> Result<(), DataLinkError> {
        self.writer.write(packet)
    }
}

impl<R: PacketRead, W: PacketWrite> PacketRead for Interface<R, W> {
    fn read(&mut self) -> Result<Packet, DataLinkError> {
        self.reader.read()
    }
}

/// Read + Write packet interface
pub trait PacketInterface {
    /// Packet reader
    type Reader: PacketRead;
    /// Packet writer
    type Writer: PacketWrite;

    /// Initialization of an interface
    ///
    /// `name` could be a network interface, device id, pcap filename, etc.
    fn init(name: &str) -> Result<Interface<Self::Reader, Self::Writer>, DataLinkError>
    where
        Self: Sized;

    /// Initialization of an interface with a packet parser
    ///
    /// `name` could be a network interface, device id, pcap filename, etc.
    fn init_with_parser(
        name: &str,
        packet_parser: PacketParser,
    ) -> Result<Interface<Self::Reader, Self::Writer>, DataLinkError>
    where
        Self: Sized;
}

/// Read-only packet interface
pub trait PacketInterfaceRead {
    /// Packet reader
    type Reader: PacketRead;

    /// Initialization of an interface
    ///
    /// `name` could be a network interface, device id, pcap filename, etc.
    fn init(name: &str) -> Result<InterfaceReader<Self::Reader>, DataLinkError>
    where
        Self: Sized;

    /// Initialization of an interface with a packet parser
    ///
    /// `name` could be a network interface, device id, pcap filename, etc.
    fn init_with_parser(
        name: &str,
        packet_parser: PacketParser,
    ) -> Result<InterfaceReader<Self::Reader>, DataLinkError>
    where
        Self: Sized;
}

/// Write-only packet interface
pub trait PacketInterfaceWrite {
    /// Packet writer
    type Writer: PacketWrite;

    /// Initialization of an interface
    ///
    /// `name` could be a network interface, device id, pcap filename, etc.
    fn init(name: &str) -> Result<InterfaceWriter<Self::Writer>, DataLinkError>
    where
        Self: Sized;
}

/// Packet read on an interface
pub trait PacketRead {
    /// Read packet
    fn read(&mut self) -> Result<Packet, DataLinkError>;
}

/// Packet write on an interface
pub trait PacketWrite {
    /// Write packet
    fn write(&mut self, packet: Packet) -> Result<(), DataLinkError>;
}

/// Unimplemented packet writer
pub struct UnimplementedWriter;
impl PacketWrite for UnimplementedWriter {
    fn write(&mut self, _packet: Packet) -> Result<(), DataLinkError> {
        unimplemented!()
    }
}
/// Unimplemented packet reader
pub struct UnimplementedReader;
impl PacketRead for UnimplementedReader {
    fn read(&mut self) -> Result<Packet, DataLinkError> {
        unimplemented!()
    }
}

/// Reference to read-only interface
pub struct InterfaceReaderRef<'a, T>
where
    T: PacketRead,
{
    reader: &'a mut T,
    metadata: &'a InterfaceMetadata,
}

impl<'a, T> InterfaceReaderRef<'a, T>
where
    T: PacketRead,
{
    /// Get the mac address of the interface
    pub fn mac_address(&self) -> Option<&MacAddress> {
        self.metadata.mac_address.as_ref()
    }
}

/// Reference to write-only interface
pub struct InterfaceWriterRef<'a, T>
where
    T: PacketWrite,
{
    writer: &'a mut T,
    metadata: &'a InterfaceMetadata,
}

impl<'a, T> InterfaceWriterRef<'a, T>
where
    T: PacketWrite,
{
    /// Get the mac address of the interface
    pub fn mac_address(&self) -> Option<&MacAddress> {
        self.metadata.mac_address.as_ref()
    }
}

/// Read-only interface
pub struct InterfaceReader<R>
where
    R: PacketRead,
{
    reader: R,
    metadata: InterfaceMetadata,
}

impl<R> InterfaceReader<R>
where
    R: PacketRead,
{
    /// Initialize read-only interface
    pub fn init<T: PacketInterfaceRead<Reader = R>>(
        name: &str,
    ) -> Result<InterfaceReader<T::Reader>, DataLinkError>
    where
        Self: Sized,
    {
        T::init(name)
    }

    /// Initialize read-only interface with custom parser
    pub fn init_with_parser<T: PacketInterfaceRead<Reader = R>>(
        name: &str,
        packet_parser: PacketParser,
    ) -> Result<InterfaceReader<T::Reader>, DataLinkError>
    where
        Self: Sized,
    {
        T::init_with_parser(name, packet_parser)
    }

    /// Get the mac address of the interface
    pub fn mac_address(&self) -> Option<&MacAddress> {
        self.metadata.mac_address.as_ref()
    }
}

/// Write-only interface
pub struct InterfaceWriter<W>
where
    W: PacketWrite,
{
    writer: W,
    metadata: InterfaceMetadata,
}

impl<W> InterfaceWriter<W>
where
    W: PacketWrite,
{
    /// Initialize write-only interface
    pub fn init<T: PacketInterfaceWrite<Writer = W>>(
        name: &str,
    ) -> Result<InterfaceWriter<T::Writer>, DataLinkError>
    where
        Self: Sized,
    {
        T::init(name)
    }

    /// Get the mac address of the interface
    pub fn mac_address(&self) -> Option<&MacAddress> {
        self.metadata.mac_address.as_ref()
    }
}

impl<'a, T: PacketRead> PacketRead for InterfaceReaderRef<'a, T> {
    fn read(&mut self) -> Result<Packet, DataLinkError> {
        self.reader.read()
    }
}

impl<T: PacketRead> PacketRead for InterfaceReader<T> {
    fn read(&mut self) -> Result<Packet, DataLinkError> {
        self.reader.read()
    }
}

impl<'a, T: PacketWrite> PacketWrite for InterfaceWriterRef<'a, T> {
    fn write(&mut self, packet: Packet) -> Result<(), DataLinkError> {
        self.writer.write(packet)
    }
}

impl<T: PacketWrite> PacketWrite for InterfaceWriter<T> {
    fn write(&mut self, packet: Packet) -> Result<(), DataLinkError> {
        self.writer.write(packet)
    }
}

impl<R: PacketRead, W: PacketWrite> Iterator for Interface<R, W> {
    type Item = Packet;

    fn next(&mut self) -> Option<Self::Item> {
        self.reader.read().ok()
    }
}

impl<T: PacketRead> Iterator for InterfaceReaderRef<'_, T> {
    type Item = Packet;

    fn next(&mut self) -> Option<Self::Item> {
        self.reader.read().ok()
    }
}

impl<T: PacketRead> Iterator for InterfaceReader<T> {
    type Item = Packet;

    fn next(&mut self) -> Option<Self::Item> {
        self.reader.read().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(dead_code)]
    struct DummyInterface {
        reader: DummyReader,
        writer: DummyWriter,
    }

    #[derive(Default)]
    #[allow(dead_code)]
    struct DummyReader {
        packet_parser: PacketParser,
    }

    #[derive(Debug, Default)]
    struct DummyWriter {
        write_count: usize,
    }

    impl PacketInterface for DummyInterface {
        type Reader = DummyReader;
        type Writer = DummyWriter;

        fn init(name: &str) -> Result<Interface<Self::Reader, Self::Writer>, DataLinkError>
        where
            Self: Sized,
        {
            <Self as PacketInterface>::init_with_parser(name, PacketParser::new())
        }

        fn init_with_parser(
            _name: &str,
            packet_parser: PacketParser,
        ) -> Result<Interface<Self::Reader, Self::Writer>, DataLinkError>
        where
            Self: Sized,
        {
            Ok(Interface {
                reader: DummyReader { packet_parser },
                writer: DummyWriter { write_count: 0 },
                metadata: InterfaceMetadata { mac_address: None },
            })
        }
    }

    impl PacketInterfaceRead for DummyInterface {
        type Reader = DummyReader;

        fn init(name: &str) -> Result<InterfaceReader<Self::Reader>, DataLinkError>
        where
            Self: Sized,
        {
            <Self as PacketInterfaceRead>::init_with_parser(name, PacketParser::new())
        }

        fn init_with_parser(
            name: &str,
            packet_parser: PacketParser,
        ) -> Result<InterfaceReader<Self::Reader>, DataLinkError>
        where
            Self: Sized,
        {
            let (reader, _writer) =
                <DummyInterface as PacketInterface>::init_with_parser(name, packet_parser)?
                    .into_split();
            Ok(reader)
        }
    }

    impl PacketInterfaceWrite for DummyInterface {
        type Writer = DummyWriter;

        fn init(name: &str) -> Result<InterfaceWriter<Self::Writer>, DataLinkError>
        where
            Self: Sized,
        {
            let (_reader, writer) = <DummyInterface as PacketInterface>::init(name)?.into_split();
            Ok(writer)
        }
    }

    impl PacketRead for DummyReader {
        fn read(&mut self) -> Result<Packet, DataLinkError> {
            Ok(Packet::new())
        }
    }

    impl PacketWrite for DummyWriter {
        fn write(&mut self, _packet: Packet) -> Result<(), DataLinkError> {
            self.write_count += 1;
            Ok(())
        }
    }

    #[test]
    fn test_interface_default() {
        let mut interface = Interface::init::<DummyInterface>("test").unwrap();
        let pkt = interface.read().unwrap();
        interface.write(pkt).unwrap();

        assert_eq!(1, interface.writer.write_count);
    }

    #[test]
    fn test_interface_reader() {
        let mut interface = InterfaceReader::init::<DummyInterface>("test").unwrap();
        let _pkt = interface.read().unwrap();
    }

    #[test]
    fn test_interface_writer() {
        let mut interface = InterfaceWriter::init::<DummyInterface>("test").unwrap();
        let pkt = Packet::new();
        interface.write(pkt).unwrap();

        assert_eq!(1, interface.writer.write_count);
    }

    #[test]
    fn test_interface_split_ref() {
        let mut interface = Interface::init::<DummyInterface>("test").unwrap();
        let (mut reader, mut writer) = interface.split();

        let pkt = reader.read().unwrap();
        writer.write(pkt).unwrap();

        assert_eq!(1, writer.writer.write_count);
    }

    #[test]
    fn test_interface_split_owned() {
        let interface = Interface::init::<DummyInterface>("test").unwrap();
        let (mut reader, mut writer) = interface.into_split();

        let pkt = reader.read().unwrap();
        writer.write(pkt).unwrap();

        assert_eq!(1, writer.writer.write_count);
    }

    #[test]
    fn test_interface_iter() {
        let mut interface = Interface::init::<DummyInterface>("test").unwrap();
        assert!(interface.next().is_some());
    }

    #[test]
    fn test_interface_reader_iter() {
        let mut interface = InterfaceReader::init::<DummyInterface>("test").unwrap();
        assert!(interface.next().is_some());
    }

    #[test]
    fn test_interface_reader_ref_iter() {
        let mut interface = Interface::init::<DummyInterface>("test").unwrap();
        let (mut reader, _writer) = interface.split();
        assert!(reader.next().is_some());
    }
}
