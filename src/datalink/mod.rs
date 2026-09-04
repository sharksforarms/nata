/*!
Read and Write packets over an interface

# Interface Types

Some interface types are enabled via crate features.

| Type | Feature | Description
|-----------|------------------|------------
| [Pnet] | default | Use [libpnet] cross-platform abstraction over a network interface
| `Pcap` | libpcap | Use libpcap for I/O on a network interface

[Pnet]: crate::datalink::pnet::Pnet
[libpnet]: https://github.com/libpnet/libpnet

# Example

The backend-specific `open` helpers are the easiest entry points. The
fallible iterator preserves capture and parse errors:

```rust,ignore
use nata::datalink::{pcap::Pcap, PacketReadExt};

let mut interface = Pcap::open("lo").unwrap();
let (mut reader, _writer) = interface.into_split();

for packet in reader.try_iter() {
    println!("Packet: {:?}", packet.unwrap());
}
```

`Interface::init` remains available when selecting a backend through the
generic `PacketInterface` abstraction.
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
    /// Read one packet.
    ///
    /// Implementations use [`DataLinkError::Eof`] to signal a normal end of a
    /// finite source such as a PCAP file.
    fn read(&mut self) -> Result<Packet, DataLinkError>;

    /// Read the next packet, treating end-of-file as a normal end of stream.
    fn next_packet(&mut self) -> Result<Option<Packet>, DataLinkError> {
        match self.read() {
            Ok(packet) => Ok(Some(packet)),
            Err(DataLinkError::Eof) => Ok(None),
            Err(error) => Err(error),
        }
    }
}

/// Extension methods for fallible packet iteration.
pub trait PacketReadExt: PacketRead {
    /// Iterate over packets while preserving read and parse errors.
    fn try_iter(&mut self) -> impl Iterator<Item = Result<Packet, DataLinkError>> + '_
    where
        Self: Sized,
    {
        PacketTryIter { reader: self }
    }
}

impl<T: PacketRead + ?Sized> PacketReadExt for T {}

/// A fallible packet iterator backed by a [`PacketRead`] implementation.
struct PacketTryIter<'a, R: PacketRead + ?Sized> {
    reader: &'a mut R,
}

impl<R: PacketRead + ?Sized> Iterator for PacketTryIter<'_, R> {
    type Item = Result<Packet, DataLinkError>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.reader.next_packet() {
            Ok(Some(packet)) => Some(Ok(packet)),
            Ok(None) => None,
            Err(error) => Some(Err(error)),
        }
    }
}

/// Packet write on an interface
pub trait PacketWrite {
    /// Write one packet, finalizing it before serialization in the built-in
    /// backends.
    fn write(&mut self, packet: Packet) -> Result<(), DataLinkError>;

    /// Send a packet.
    fn send(&mut self, packet: Packet) -> Result<(), DataLinkError> {
        self.write(packet)
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
    fn test_interface_try_iter() {
        let mut interface = Interface::init::<DummyInterface>("test").unwrap();
        assert!(matches!(interface.try_iter().next(), Some(Ok(_))));
    }

    #[test]
    fn test_interface_reader_try_iter() {
        let mut interface = InterfaceReader::init::<DummyInterface>("test").unwrap();
        assert!(matches!(interface.try_iter().next(), Some(Ok(_))));
    }

    #[test]
    fn test_interface_reader_ref_try_iter() {
        let mut interface = Interface::init::<DummyInterface>("test").unwrap();
        let (mut reader, _writer) = interface.split();
        assert!(matches!(reader.try_iter().next(), Some(Ok(_))));
    }

    struct EofReader {
        yielded: bool,
    }

    impl PacketRead for EofReader {
        fn read(&mut self) -> Result<Packet, DataLinkError> {
            if self.yielded {
                Err(DataLinkError::Eof)
            } else {
                self.yielded = true;
                Ok(Packet::new())
            }
        }
    }

    struct ErrorReader;

    impl PacketRead for ErrorReader {
        fn read(&mut self) -> Result<Packet, DataLinkError> {
            Err(DataLinkError::BufferError)
        }
    }

    #[test]
    fn test_packet_try_iter_stops_at_eof() {
        let mut reader = EofReader { yielded: false };
        let mut packets = reader.try_iter();

        assert!(matches!(packets.next(), Some(Ok(_))));
        assert!(packets.next().is_none());
    }

    #[test]
    fn test_packet_try_iter_preserves_errors() {
        let mut reader = ErrorReader;
        let mut packets = reader.try_iter();

        assert!(matches!(
            packets.next(),
            Some(Err(DataLinkError::BufferError))
        ));
    }
}
