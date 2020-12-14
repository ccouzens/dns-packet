use color_eyre::eyre::Result;
use dns_packet::DnsPacket;
use dns_packet::DnsPacketParseError;
use pretty_hex::PrettyHex;
use std::convert::TryFrom;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::net::SocketAddrV4;
use std::net::UdpSocket;
use structopt::StructOpt;
use thiserror::Error;

#[derive(Error, Debug)]
enum MainError {
    #[error("label {label:} incorrect size")]
    LabelSize { label: String },
    #[error("label {label:} contains invalid characters")]
    LabelInvalidCharacter { label: String },
    #[error("Error during bind")]
    BindError(#[source] std::io::Error),
    #[error("Error during send")]
    SendError(#[source] std::io::Error),
    #[error("Error during receive")]
    ReceiveError(#[source] std::io::Error),
    #[error("Response received from unexpected host {0:}")]
    UnexpectedReceive(SocketAddr),
    #[error("Failed to read {0:} from response data")]
    InvalidBuffer(usize),
    #[error("Failed to parse DNS response")]
    InvalidDnsPacket(#[source] DnsPacketParseError),
}

#[derive(StructOpt, Debug)]
struct Opt {
    host_name: String,
    resolver: Ipv4Addr,
}

fn main() -> Result<()> {
    color_eyre::install()?;
    let opt = Opt::from_args();
    let mut request_packet = Vec::new();
    // Header ID
    request_packet.extend_from_slice(&[0, 0]);
    // Header QR, Opcode, AA, TC and RD
    request_packet.push(0b0000_0001);
    // Header RA, Z, RCODE
    request_packet.push(0b0000_0000);
    // Header QDCOUNT
    request_packet.extend_from_slice(&[0, 1]);
    // Header ANCOUNT
    request_packet.extend_from_slice(&[0, 0]);
    // Header NSCOUNT
    request_packet.extend_from_slice(&[0, 0]);
    // Header ARCOUNT
    request_packet.extend_from_slice(&[0, 0]);

    // The question Label Sequence
    for label in opt.host_name.split('.') {
        let length = u8::try_from(label.len())
            .ok()
            .and_then(|l| if l == 0 || l > 63 { None } else { Some(l) })
            .ok_or_else(|| MainError::LabelSize {
                label: label.to_string(),
            })?;
        request_packet.push(length);
        for byte in label.bytes() {
            match byte {
                b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z' => request_packet.push(byte),
                _ => {
                    return Err(MainError::LabelInvalidCharacter {
                        label: label.to_string(),
                    }
                    .into())
                }
            }
        }
    }
    request_packet.push(0);

    // The question Type
    request_packet.extend_from_slice(&[0, 1]);
    // The question Class
    request_packet.extend_from_slice(&[0, 1]);

    println!("request packet: {:?}", request_packet.hex_dump());

    let resolver_address = SocketAddrV4::new(opt.resolver, 53);

    let socket = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))
        .map_err(MainError::BindError)?;

    socket
        .send_to(&request_packet, resolver_address)
        .map_err(MainError::SendError)?;

    let mut buf = [0; 512];
    let (number_of_bytes_received, src_addr) = socket
        .recv_from(&mut buf)
        .map_err(MainError::ReceiveError)?;
    if src_addr != std::net::SocketAddr::V4(resolver_address) {
        return Err(MainError::UnexpectedReceive(src_addr).into());
    }

    let response_packet = buf
        .get(0..number_of_bytes_received)
        .ok_or(MainError::InvalidBuffer(number_of_bytes_received))?;

    println!("\nresponse packet: {:?}", response_packet.hex_dump());

    let dns_packet = DnsPacket::try_from(response_packet).map_err(MainError::InvalidDnsPacket)?;

    println!("\n{:?}", dns_packet.answers);

    Ok(())
}
