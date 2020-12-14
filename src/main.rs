use pretty_hex::PrettyHex;
use std::convert::TryFrom;
use std::net::Ipv4Addr;
use structopt::StructOpt;
use thiserror::Error;

#[derive(Error, Debug)]
enum MainError {
    #[error("label {label:} incorrect size")]
    LabelSize { label: String },
    #[error("label {label:} contains invalid characters")]
    LabelInvalidCharacter { label: String },
}

#[derive(StructOpt, Debug)]
struct Opt {
    host_name: String,
    resolver: Ipv4Addr,
}

fn main() -> Result<(), MainError> {
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
                    })
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
    Ok(())
}
