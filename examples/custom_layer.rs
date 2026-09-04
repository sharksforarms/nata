use hexlit::hex;
use nata::layer::ether::Ether;
use nata::layer::ip::Ipv4;
use nata::layer::tcp::Tcp;
use nata::layer::LayerError;
use nata::layer::{LayerOwned, PacketLayer};
use nata::packet::Parser;
use std::vec::Vec;

#[derive(Debug, Default, Clone)]
struct Http {
    data: String,
}

impl PacketLayer for Http {
    fn finalize(&mut self, _prev: &[LayerOwned], _next: &[LayerOwned]) -> Result<(), LayerError> {
        Ok(())
    }

    fn parse(input: &[u8]) -> Result<(&[u8], Self), LayerError>
    where
        Self: Sized,
    {
        let http = Http {
            data: String::from_utf8_lossy(input).to_string(),
        };
        Ok(([].as_ref(), http))
    }

    fn to_bytes(&self) -> Result<Vec<u8>, LayerError> {
        Ok(self.data.as_bytes().to_vec())
    }
}

fn main() {
    let parser = Parser::new()
        .bind::<Ether, Ipv4>(|_, _| true)
        .bind::<Ipv4, Tcp>(|_, _| true)
        .bind::<Tcp, Http>(|tcp, _| tcp.dport == 80);

    // Ether / IP / TCP / "GET /example HTTP/1.1"
    let test_data = hex!("ffffffffffff0000000000000800450000330001000040067cc27f0000017f00000100140050000000000000000050022000ffa20000474554202f6578616d706c6520485454502f312e31");
    let packet = parser.parse::<Ether>(&test_data).unwrap();
    assert!(packet.has::<Http>());
    dbg!(packet);
}
