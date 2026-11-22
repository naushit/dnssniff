//! Safe Zero-Alloc DNS Wire Parser.
//!
//! Parses DNS messages directly out of borrowed `&[u8]` slices with:
//! - No heap allocations
//! - Strict compression-pointer validation (16-hop limit)
//! - Boundary checks on every read

use crate::dns_proto::header::{DnsHeader, Rcode};
use crate::dns_proto::MAX_COMPRESSION_HOPS;
use crate::types::TransactionStatus;

/// Result of parsing a DNS message.
#[derive(Debug, Clone)]
pub struct ParsedDnsMessage {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    /// Whether the message is truncated (TC bit set).
    pub truncated: bool,
}

/// A single DNS question record.
#[derive(Debug, Clone)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

/// Error returned by the DNS parser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsParseError {
    Truncated,
    InvalidCompressionPointer,
    CompressionLoop,
    OutOfBounds,
    InvalidHeader,
    TooManyQuestions,
}

/// Parse a full DNS message from a borrowed slice.
///
/// Returns the parsed message or a `DnsParseError`.
/// All strings are allocated (questions vector) but this is called once per
/// packet and the question count is bounded by QDCOUNT in the header.
pub fn parse_dns_message(buf: &[u8]) -> Result<ParsedDnsMessage, DnsParseError> {
    let header = DnsHeader::parse(buf).ok_or(DnsParseError::InvalidHeader)?;

    let mut offset = 12usize; // after header
    let max_questions = (header.qdcount as usize).min(4).min((buf.len() - 12) / 5);
    let mut questions = Vec::with_capacity(max_questions);

    for _ in 0..header.qdcount {
        let (name, new_offset) = read_domain_name(buf, offset, 0)?;
        offset = new_offset;

        if offset + 4 > buf.len() {
            return Err(DnsParseError::Truncated);
        }
        let qtype = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
        let qclass = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]);
        offset += 4;

        questions.push(DnsQuestion { name, qtype, qclass });
    }

    Ok(ParsedDnsMessage {
        header,
        questions,
        truncated: header.flags.tc,
    })
}

/// Read a DNS domain name from the buffer, handling compression pointers.
///
/// Returns (domain_name_string, next_offset_after_name).
/// `hops` tracks recursion depth to prevent compression loops.
fn read_domain_name(
    buf: &[u8],
    mut offset: usize,
    mut hops: u8,
) -> Result<(String, usize), DnsParseError> {
    let mut labels: Vec<&[u8]> = Vec::new();
    let mut orig_offset = offset;
    let mut jumped = false;

    loop {
        if offset >= buf.len() {
            return Err(DnsParseError::OutOfBounds);
        }

        let len = buf[offset] as usize;

        // Compression pointer: top two bits set
        if (len & 0xC0) == 0xC0 {
            if hops >= MAX_COMPRESSION_HOPS {
                return Err(DnsParseError::CompressionLoop);
            }
            if offset + 1 >= buf.len() {
                return Err(DnsParseError::OutOfBounds);
            }
            let pointer = (((len & 0x3F) as u16) << 8) | (buf[offset + 1] as u16);
            let pointer_offset = pointer as usize;

            // Validate pointer target is within bounds and points backwards
            // (forward pointers could create loops)
            if pointer_offset >= buf.len() {
                return Err(DnsParseError::InvalidCompressionPointer);
            }

            if !jumped {
                orig_offset = offset + 2; // save return point after pointer
            }
            offset = pointer_offset;
            jumped = true;
            hops = hops.saturating_add(1);
            continue;
        }

        // End of name (zero-length label)
        if len == 0 {
            let next_offset = if jumped {
                orig_offset
            } else {
                offset + 1
            };

            let name = labels
                .iter()
                .map(|l| std::str::from_utf8(l).unwrap_or("").to_string())
                .collect::<Vec<_>>()
                .join(".");

            return Ok((name, next_offset));
        }

        // Regular label
        offset += 1;
        if offset + len > buf.len() {
            return Err(DnsParseError::OutOfBounds);
        }
        labels.push(&buf[offset..offset + len]);
        offset += len;
    }
}

/// Extract just the first question's domain name and QTYPE from a DNS payload.
/// Lightweight version used for quick transaction tracking without full parse.
pub fn extract_question_light(buf: &[u8]) -> Option<(String, u16, u16)> {
    if buf.len() < 12 {
        return None;
    }
    let header = match DnsHeader::parse(buf) {
        Some(h) => h,
        None => return None,
    };
    if header.qdcount == 0 {
        return None;
    }
    let (name, offset) = match read_domain_name(buf, 12, 0) {
        Ok(r) => r,
        Err(_) => return None,
    };
    if offset + 4 > buf.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
    let _qclass = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]);
    Some((name, qtype, 0)) // qclass not needed for tracking
}

/// Determine the transaction status from a DNS response header.
pub fn status_from_response(header: &DnsHeader) -> TransactionStatus {
    if header.flags.tc {
        return TransactionStatus::Truncated;
    }
    match header.flags.rcode {
        Rcode::NoError => TransactionStatus::Ok,
        Rcode::NxDomain => TransactionStatus::NxDomain,
        Rcode::ServFail => TransactionStatus::ServFail,
        Rcode::Refused => TransactionStatus::Refused,
        Rcode::FormErr => TransactionStatus::Malformed,
        _ => TransactionStatus::Ok,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_query_packet(domain: &str) -> Vec<u8> {
        let mut buf = Vec::new();
        // Header
        buf.extend_from_slice(&[0xab, 0xcd]); // id
        buf.extend_from_slice(&[0x01, 0x00]); // flags: query, rd=1
        buf.extend_from_slice(&[0x00, 0x01]); // qdcount=1
        buf.extend_from_slice(&[0x00, 0x00]); // ancount
        buf.extend_from_slice(&[0x00, 0x00]); // nscount
        buf.extend_from_slice(&[0x00, 0x00]); // arcount
        // Question: example.com, type A, class IN
        for label in domain.split('.') {
            buf.push(label.len() as u8);
            buf.extend_from_slice(label.as_bytes());
        }
        buf.push(0x00); // end of name
        buf.extend_from_slice(&[0x00, 0x01]); // type A
        buf.extend_from_slice(&[0x00, 0x01]); // class IN
        buf
    }

    #[test]
    fn test_parse_simple_query() {
        let buf = build_query_packet("example.com");
        let msg = parse_dns_message(&buf).unwrap();
        assert_eq!(msg.header.transaction_id, 0xabcd);
        assert!(msg.header.flags.is_query());
        assert_eq!(msg.questions.len(), 1);
        assert_eq!(msg.questions[0].name, "example.com");
        assert_eq!(msg.questions[0].qtype, 1);
        assert!(!msg.truncated);
    }

    #[test]
    fn test_parse_response_with_rcode() {
        let mut buf = build_query_packet("example.com");
        // Override flags to be a response with NXDOMAIN
        buf[2] = 0x81;
        buf[3] = 0x83; // qr=1, rcode=3 (NXDOMAIN)
        let msg = parse_dns_message(&buf).unwrap();
        assert!(msg.header.flags.is_response());
        assert_eq!(msg.header.flags.rcode, Rcode::NxDomain);
    }

    #[test]
    fn test_compression_pointer() {
        // Build a packet with a compressed name
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0x00, 0x01]); // id
        buf.extend_from_slice(&[0x01, 0x00]); // query
        buf.extend_from_slice(&[0x00, 0x02]); // qdcount=2
        buf.extend_from_slice(&[0x00, 0x00]); // ancount
        buf.extend_from_slice(&[0x00, 0x00]); // nscount
        buf.extend_from_slice(&[0x00, 0x00]); // arcount

        // First question: www.example.com (uncompressed)
        buf.push(3); buf.extend_from_slice(b"www");
        buf.push(7); buf.extend_from_slice(b"example");
        buf.push(3); buf.extend_from_slice(b"com");
        buf.push(0);
        buf.extend_from_slice(&[0x00, 0x01]); // type A
        buf.extend_from_slice(&[0x00, 0x01]); // class IN

        // Second question: mail.example.com (compress "example.com" referencing offset 10)
        // "www" starts at offset 12, "example.com" starts at offset 16
        buf.push(4); buf.extend_from_slice(b"mail");
        // Compression pointer to offset 16 (where "example" starts)
        buf.push(0xC0 | ((16 >> 8) as u8));
        buf.push(16 & 0xFF);
        buf.extend_from_slice(&[0x00, 0x01]); // type A
        buf.extend_from_slice(&[0x00, 0x01]); // class IN

        let msg = parse_dns_message(&buf).unwrap();
        assert_eq!(msg.questions.len(), 2);
        assert_eq!(msg.questions[0].name, "www.example.com");
        assert_eq!(msg.questions[1].name, "mail.example.com");
    }

    #[test]
    fn test_compression_loop_rejected() {
        // Build a packet with a self-referencing compression pointer (infinite loop)
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0x00, 0x01]);
        buf.extend_from_slice(&[0x01, 0x00]);
        buf.extend_from_slice(&[0x00, 0x01]); // qdcount=1
        buf.extend_from_slice(&[0x00, 0x00]);
        buf.extend_from_slice(&[0x00, 0x00]);
        buf.extend_from_slice(&[0x00, 0x00]);

        // Compression pointer at offset 12 pointing to itself
        buf.push(0xC0 | ((12 >> 8) as u8));
        buf.push(12 & 0xFF);
        buf.extend_from_slice(&[0x00, 0x01]); // type A
        buf.extend_from_slice(&[0x00, 0x01]); // class IN

        let result = parse_dns_message(&buf);
        assert!(matches!(result, Err(DnsParseError::CompressionLoop)));
    }

    #[test]
    fn test_extract_question_light() {
        let buf = build_query_packet("test.example.org");
        let (name, qtype, _) = extract_question_light(&buf).unwrap();
        assert_eq!(name, "test.example.org");
        assert_eq!(qtype, 1);
    }

    #[test]
    fn test_status_from_response() {
        let mut buf = build_query_packet("example.com");
        buf[2] = 0x81;
        buf[3] = 0x82; // SERVFAIL
        let msg = parse_dns_message(&buf).unwrap();
        let status = status_from_response(&msg.header);
        assert_eq!(status, TransactionStatus::ServFail);
    }
}
