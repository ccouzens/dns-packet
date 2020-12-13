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
    questions: Vec<Question>,
    answers: Vec<RecordPreamble>,
}

#[derive(Debug, PartialEq)]
enum RecordType {
    AddressRecord,
    Other,
}

#[derive(Debug, PartialEq)]
enum Class {
    Internet,
    Other,
}

#[derive(Debug, PartialEq)]
struct Question {
    name: String,
    r#type: RecordType,
    class: Class,
}

#[derive(Error, Debug, PartialEq)]
enum DnsPacketParseError {
    #[error("byte index {index:?} was out of bounds (length: {length:?})")]
    OutOfBounds { index: usize, length: usize },
    #[error("too many jumps reading label")]
    JumpLimitExceeded,
}

struct LabelSequenceIterator<'a, 'b> {
    position: u16,
    packet: &'a [u8],
    global_position: &'b mut u16,
    jump_counter: u8,
}

impl<'a, 'b> LabelSequenceIterator<'a, 'b> {
    fn new(position: &'b mut u16, packet: &'a [u8]) -> Self {
        Self {
            position: *position,
            packet,
            global_position: position,
            jump_counter: 0,
        }
    }

    fn read_section(&mut self) -> Result<Option<&'a [u8]>, DnsPacketParseError> {
        while get8(self.position as usize, self.packet)? & 0b11000000 == 0b11000000 {
            if self.jump_counter == 0 {
                *self.global_position += 2;
            }
            self.position = get16(self.position as usize, self.packet)? & 0b0011_1111_1111_1111;
            self.jump_counter += 1;
            if self.jump_counter > 5 {
                return Err(DnsPacketParseError::JumpLimitExceeded);
            }
        }
        let length = get8(self.position as usize, self.packet)? & 0b0011_1111;
        if self.jump_counter == 0 {
            *self.global_position += 1 + length as u16;
        }
        if length == 0 {
            return Ok(None);
        }
        let old_position = self.position as usize + 1;
        let new_position = old_position + length as usize;
        let content = self.packet.get(old_position..new_position).ok_or_else(|| {
            DnsPacketParseError::OutOfBounds {
                index: new_position - 1,
                length: self.packet.len(),
            }
        })?;
        self.position = self.position + length as u16 + 1;
        Ok(Some(content))
    }
}

impl<'a, 'b> Iterator for LabelSequenceIterator<'a, 'b> {
    type Item = Result<&'a [u8], DnsPacketParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.read_section().transpose()
    }
}

#[derive(Debug, PartialEq)]
struct RecordPreamble {
    question: Question,
    time_to_live: u32,
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

fn get32(index: usize, value: &[u8]) -> Result<u32, DnsPacketParseError> {
    let d = get8(index + 3, value)? as u32;
    let c = get8(index + 2, value)? as u32;
    let b = get8(index + 1, value)? as u32;
    let a = get8(index, value)? as u32;
    Ok((a << 24) + (b << 16) + (c << 8) + d)
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

        let mut position = 12;

        let mut questions = Vec::with_capacity(question_count as usize);
        for _ in 0..question_count {
            questions.push(Question::try_from((value, &mut position))?);
        }

        let answers: Vec<RecordPreamble> = (0..answer_count)
            .map(|_| RecordPreamble::try_from((value, &mut position)))
            .collect::<Result<Vec<RecordPreamble>, Self::Error>>()?;

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
            questions,
            answers,
        })
    }
}

impl TryFrom<(&[u8], &mut u16)> for Question {
    type Error = DnsPacketParseError;

    fn try_from((value, position): (&[u8], &mut u16)) -> Result<Self, Self::Error> {
        let mut name = String::new();
        for label in LabelSequenceIterator::new(position, value) {
            if !name.is_empty() {
                name.push('.');
            }
            name.extend(label?.iter().map(|&b| char::from(b)));
        }
        let class = match get16(*position as usize + 2, value)? {
            1 => Class::Internet,
            _ => Class::Other,
        };
        let r#type = match get16(*position as usize, value)? {
            1 => RecordType::AddressRecord,
            _ => RecordType::Other,
        };
        *position += 4;
        Ok(Question {
            name,
            class,
            r#type,
        })
    }
}
impl TryFrom<(&[u8], &mut u16)> for RecordPreamble {
    type Error = DnsPacketParseError;

    fn try_from((value, position): (&[u8], &mut u16)) -> Result<Self, Self::Error> {
        let question = Question::try_from((value, &mut *position))?;
        let time_to_live = get32((*position) as usize, value)?;
        *position += 4;
        Ok(Self {
            question,
            time_to_live,
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

    #[test]
    fn label_sequence() {
        let mut position = 12;
        let i = LabelSequenceIterator::new(&mut position, QUERY_PACKET);
        assert_eq!(
            i.collect::<Result<Vec<_>, _>>(),
            Ok(vec!["google".as_bytes(), "com".as_bytes()])
        );
        assert_eq!(position, 24);

        position = 12;
        let j = LabelSequenceIterator::new(&mut position, RESPONSE_PACKET);
        assert_eq!(
            j.collect::<Result<Vec<_>, _>>(),
            Ok(vec!["google".as_bytes(), "com".as_bytes()])
        );
        assert_eq!(position, 24);

        position = 28;
        let k = LabelSequenceIterator::new(&mut position, RESPONSE_PACKET);
        assert_eq!(
            k.collect::<Result<Vec<_>, _>>(),
            Ok(vec!["google".as_bytes(), "com".as_bytes()])
        );
        assert_eq!(position, 30);
    }

    #[test]
    fn questions() {
        assert_eq!(
            DnsPacket::try_from(QUERY_PACKET).unwrap().questions,
            vec![Question {
                name: "google.com".to_string(),
                r#type: RecordType::AddressRecord,
                class: Class::Internet
            }]
        );
        assert_eq!(
            DnsPacket::try_from(RESPONSE_PACKET).unwrap().questions,
            vec![Question {
                name: "google.com".to_string(),
                r#type: RecordType::AddressRecord,
                class: Class::Internet
            }]
        );
    }
    #[test]
    fn answers() {
        assert_eq!(DnsPacket::try_from(QUERY_PACKET).unwrap().answers, vec![]);
        assert_eq!(
            DnsPacket::try_from(RESPONSE_PACKET).unwrap().answers,
            vec![RecordPreamble {
                question: Question {
                    name: "google.com".to_string(),
                    r#type: RecordType::AddressRecord,
                    class: Class::Internet
                },
                time_to_live: 264
            }]
        );
    }
}
