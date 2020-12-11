use std::convert::TryFrom;
use thiserror::Error;

#[derive(Debug, PartialEq)]
enum QueryResponse {
    Query = 0,
    Response = 1,
}

#[derive(Debug, PartialEq)]
enum Opcode {
    Query = 0,
    IQuery = 1,
    Status = 2,
    Notify = 4,
    Update = 5,
    DNSStatefulOperations = 6,
    Unassigned,
}

#[derive(Debug, PartialEq)]
enum RCode {
    FormErr = 1,
    ServFail = 2,
    NXDomain = 3,
    NotImp = 4,
    Refused = 5,
    YXDomain = 6,
    YXRRSet = 7,
    NXRRSet = 8,
    NotAuth = 9,
    NotZone = 10,
    DSOTYPENI = 11,
    Unassigned,
}

#[derive(Debug)]
struct DnsPacket {
    packet_identifier: u16,
    query_response: QueryResponse,
    operation_code: Opcode,
    authoritative_answer: bool,
    truncated_message: bool,
    recursion_desired: bool,
    recursion_available: bool,
    response_code: Result<(), RCode>,
    question_count: u16,
    answer_count: u16,
    authority_count: u16,
    additional_count: u16,
}

#[derive(Error, Debug)]
enum DnsPacketParseError {
    #[error("byte index {index:?} was out of bounds (length: {length:?})")]
    OutOfBounds { index: usize, length: usize },
}

fn get8(index: usize, value: &[u8]) -> Result<u8, DnsPacketParseError> {
    value
        .get(index)
        .cloned()
        .ok_or_else(|| DnsPacketParseError::OutOfBounds {
            index,
            length: value.len(),
        })
}

fn get16(index: usize, value: &[u8]) -> Result<u16, DnsPacketParseError> {
    let b = get8(index + 1, value)? as u16;
    let a = get8(index, value)? as u16;
    Ok((a << 8) + b)
}

impl TryFrom<&[u8]> for DnsPacket {
    type Error = DnsPacketParseError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let packet_identifier = get16(0, value)?;
        let query_response = if get8(2, value)? >> 7 == 1 {
            QueryResponse::Response
        } else {
            QueryResponse::Query
        };

        let operation_code = match (get8(2, value)? >> 3) & 0b1111 {
            0 => Opcode::Query,
            1 => Opcode::IQuery,
            2 => Opcode::Status,
            4 => Opcode::Notify,
            5 => Opcode::Update,
            6 => Opcode::DNSStatefulOperations,
            _ => Opcode::Unassigned,
        };

        let authoritative_answer = (get8(2, value)? >> 2) & 1 == 1;
        let truncated_message = (get8(2, value)? >> 1) & 1 == 1;
        let recursion_desired = get8(2, value)? & 1 == 1;
        let recursion_available = get8(3, value)? >> 7 == 1;
        let response_code = match get8(3, value)? & 0b1111 {
            0 => Ok(()),
            1 => Err(RCode::FormErr),
            2 => Err(RCode::ServFail),
            3 => Err(RCode::NXDomain),
            4 => Err(RCode::NotImp),
            5 => Err(RCode::Refused),
            6 => Err(RCode::YXDomain),
            7 => Err(RCode::YXRRSet),
            8 => Err(RCode::NXRRSet),
            9 => Err(RCode::NotAuth),
            10 => Err(RCode::NotZone),
            11 => Err(RCode::DSOTYPENI),
            _ => Err(RCode::Unassigned),
        };

        let question_count = get16(4, value)?;
        let answer_count = get16(6, value)?;
        let authority_count = get16(8, value)?;
        let additional_count = get16(10, value)?;

        Ok(DnsPacket {
            packet_identifier,
            query_response,
            operation_code,
            authoritative_answer,
            truncated_message,
            recursion_desired,
            recursion_available,
            response_code,
            question_count,
            answer_count,
            authority_count,
            additional_count,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const QUERY_PACKET: &[u8] = include_bytes!("../query_packet.txt");
    const RESPONSE_PACKET: &[u8] = include_bytes!("../response_packet.txt");

    #[test]
    fn packet_identifier() {
        assert_eq!(
            DnsPacket::try_from(QUERY_PACKET).unwrap().packet_identifier,
            0x93d4
        );
        assert_eq!(
            DnsPacket::try_from(RESPONSE_PACKET)
                .unwrap()
                .packet_identifier,
            0x0a99
        );
    }

    #[test]
    fn query_response() {
        assert_eq!(
            DnsPacket::try_from(QUERY_PACKET).unwrap().query_response,
            QueryResponse::Query
        );
        assert_eq!(
            DnsPacket::try_from(RESPONSE_PACKET).unwrap().query_response,
            QueryResponse::Response
        );
    }

    #[test]
    fn operation_code() {
        assert_eq!(
            DnsPacket::try_from(QUERY_PACKET).unwrap().operation_code,
            Opcode::Query
        );
        assert_eq!(
            DnsPacket::try_from(RESPONSE_PACKET).unwrap().operation_code,
            Opcode::Query
        );
    }

    #[test]
    fn authoritative_answer() {
        assert!(
            !DnsPacket::try_from(QUERY_PACKET)
                .unwrap()
                .authoritative_answer,
        );
        assert!(
            !DnsPacket::try_from(RESPONSE_PACKET)
                .unwrap()
                .authoritative_answer,
        );
    }

    #[test]
    fn truncated_message() {
        assert!(!DnsPacket::try_from(QUERY_PACKET).unwrap().truncated_message,);
        assert!(
            !DnsPacket::try_from(RESPONSE_PACKET)
                .unwrap()
                .truncated_message,
        );
    }

    #[test]
    fn recursion_desired() {
        assert!(DnsPacket::try_from(QUERY_PACKET).unwrap().recursion_desired,);
        assert!(
            DnsPacket::try_from(RESPONSE_PACKET)
                .unwrap()
                .recursion_desired,
        );
    }

    #[test]
    fn recursion_available() {
        assert!(
            !DnsPacket::try_from(QUERY_PACKET)
                .unwrap()
                .recursion_available,
        );
        assert!(
            DnsPacket::try_from(RESPONSE_PACKET)
                .unwrap()
                .recursion_available,
        );
    }

    #[test]
    fn response_code() {
        assert_eq!(
            DnsPacket::try_from(QUERY_PACKET).unwrap().response_code,
            Ok(())
        );
        assert_eq!(
            DnsPacket::try_from(RESPONSE_PACKET).unwrap().response_code,
            Ok(())
        );
    }

    #[test]
    fn question_count() {
        assert_eq!(DnsPacket::try_from(QUERY_PACKET).unwrap().question_count, 1);
        assert_eq!(
            DnsPacket::try_from(RESPONSE_PACKET).unwrap().question_count,
            1
        );
    }

    #[test]
    fn answer_count() {
        assert_eq!(DnsPacket::try_from(QUERY_PACKET).unwrap().answer_count, 0);
        assert_eq!(
            DnsPacket::try_from(RESPONSE_PACKET).unwrap().answer_count,
            1
        );
    }

    #[test]
    fn authority_count() {
        assert_eq!(
            DnsPacket::try_from(QUERY_PACKET).unwrap().authority_count,
            0
        );
        assert_eq!(
            DnsPacket::try_from(RESPONSE_PACKET)
                .unwrap()
                .authority_count,
            0
        );
    }

    #[test]
    fn additional_count() {
        assert_eq!(
            DnsPacket::try_from(QUERY_PACKET).unwrap().additional_count,
            0
        );
        assert_eq!(
            DnsPacket::try_from(RESPONSE_PACKET)
                .unwrap()
                .additional_count,
            0
        );
    }
}
