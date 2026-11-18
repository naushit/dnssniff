//! RFC 1035 DNS Header Decoder (12 bytes, zero-copy).

use std::fmt;

/// DNS response codes (RCODE field in flags).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Rcode {
    NoError = 0,
    FormErr = 1,
    ServFail = 2,
    NxDomain = 3,
    NotImp = 4,
    Refused = 5,
    YXDomain = 6,
    YXRrset = 7,
    NXRrset = 8,
    NotAuth = 9,
    NotZone = 10,
    Other(u8),
}

impl From<u8> for Rcode {
    fn from(v: u8) -> Self {
        match v {
            0 => Rcode::NoError,
            1 => Rcode::FormErr,
            2 => Rcode::ServFail,
            3 => Rcode::NxDomain,
            4 => Rcode::NotImp,
            5 => Rcode::Refused,
            6 => Rcode::YXDomain,
            7 => Rcode::YXRrset,
            8 => Rcode::NXRrset,
            9 => Rcode::NotAuth,
            10 => Rcode::NotZone,
            other => Rcode::Other(other),
        }
    }
}

impl fmt::Display for Rcode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Rcode::NoError => write!(f, "NOERROR"),
            Rcode::FormErr => write!(f, "FORMERR"),
            Rcode::ServFail => write!(f, "SERVFAIL"),
            Rcode::NxDomain => write!(f, "NXDOMAIN"),
            Rcode::NotImp => write!(f, "NOTIMP"),
            Rcode::Refused => write!(f, "REFUSED"),
            Rcode::YXDomain => write!(f, "YXDOMAIN"),
            Rcode::YXRrset => write!(f, "YXRRSET"),
            Rcode::NXRrset => write!(f, "NXRRSET"),
            Rcode::NotAuth => write!(f, "NOTAUTH"),
            Rcode::NotZone => write!(f, "NOTZONE"),
            Rcode::Other(v) => write!(f, "RCODE{}", v),
        }
    }
}

/// DNS opcode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Opcode {
    Query = 0,
    IQuery = 1,
    Status = 2,
    Notify = 4,
    Update = 5,
    Other(u8),
}

impl From<u8> for Opcode {
    fn from(v: u8) -> Self {
        match v {
            0 => Opcode::Query,
            1 => Opcode::IQuery,
            2 => Opcode::Status,
            4 => Opcode::Notify,
            5 => Opcode::Update,
            other => Opcode::Other(other),
        }
    }
}

/// DNS flags field decoded from the 16-bit flags word.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsFlags {
    pub qr: bool,           // Query/Response
    pub opcode: Opcode,
    pub aa: bool,           // Authoritative Answer
    pub tc: bool,           // Truncated
    pub rd: bool,           // Recursion Desired
    pub ra: bool,           // Recursion Available
    pub z: bool,            // Z (reserved)
    pub ad: bool,           // Authenticated Data
    pub cd: bool,           // Checking Disabled
    pub rcode: Rcode,
}

impl DnsFlags {
    pub fn is_response(&self) -> bool {
        self.qr
    }

    pub fn is_query(&self) -> bool {
        !self.qr
    }

    pub fn is_truncated(&self) -> bool {
        self.tc
    }
}

/// 12-byte DNS header per RFC 1035 section 4.1.1.
#[derive(Debug, Clone, Copy)]
pub struct DnsHeader {
    pub transaction_id: u16,
    pub flags: DnsFlags,
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
}

impl DnsHeader {
    /// Parse a DNS header from a 12-byte slice.
    /// Returns `None` if the slice is too short.
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < 12 {
            return None;
        }

        let transaction_id = u16::from_be_bytes([buf[0], buf[1]]);
        let flags_raw = u16::from_be_bytes([buf[2], buf[3]]);

        let qr = (flags_raw & 0x8000) != 0;
        let opcode = Opcode::from(((flags_raw >> 11) & 0x0F) as u8);
        let aa = (flags_raw & 0x0400) != 0;
        let tc = (flags_raw & 0x0200) != 0;
        let rd = (flags_raw & 0x0100) != 0;
        let ra = (flags_raw & 0x0080) != 0;
        let z = (flags_raw & 0x0040) != 0;
        let ad = (flags_raw & 0x0020) != 0;
        let cd = (flags_raw & 0x0010) != 0;
        let rcode = Rcode::from((flags_raw & 0x000F) as u8);

        let qdcount = u16::from_be_bytes([buf[4], buf[5]]);
        let ancount = u16::from_be_bytes([buf[6], buf[7]]);
        let nscount = u16::from_be_bytes([buf[8], buf[9]]);
        let arcount = u16::from_be_bytes([buf[10], buf[11]]);

        Some(DnsHeader {
            transaction_id,
            flags: DnsFlags {
                qr,
                opcode,
                aa,
                tc,
                rd,
                ra,
                z,
                ad,
                cd,
                rcode,
            },
            qdcount,
            ancount,
            nscount,
            arcount,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_parse_query() {
        // Transaction ID = 0x1234, flags = 0x0100 (standard query, RD=1)
        // QDCOUNT=1, others=0
        let buf = [
            0x12, 0x34, // id
            0x01, 0x00, // flags
            0x00, 0x01, // qdcount
            0x00, 0x00, // ancount
            0x00, 0x00, // nscount
            0x00, 0x00, // arcount
        ];
        let h = DnsHeader::parse(&buf).unwrap();
        assert_eq!(h.transaction_id, 0x1234);
        assert!(h.flags.is_query());
        assert!(!h.flags.is_response());
        assert!(h.flags.rd);
        assert_eq!(h.qdcount, 1);
        assert_eq!(h.ancount, 0);
    }

    #[test]
    fn test_header_parse_response() {
        // Transaction ID = 0x9999, flags = 0x8180 (response, no error, RA=1, RD=1)
        let buf = [
            0x99, 0x99,
            0x81, 0x80,
            0x00, 0x01,
            0x00, 0x01,
            0x00, 0x00,
            0x00, 0x00,
        ];
        let h = DnsHeader::parse(&buf).unwrap();
        assert!(h.flags.is_response());
        assert!(!h.flags.is_query());
        assert!(h.flags.ra);
        assert_eq!(h.flags.rcode, Rcode::NoError);
    }

    #[test]
    fn test_header_nxdomain() {
        let buf = [
            0x00, 0x01,
            0x81, 0x83, // response, rcode=3 (NXDOMAIN)
            0x00, 0x01,
            0x00, 0x00,
            0x00, 0x00,
            0x00, 0x00,
        ];
        let h = DnsHeader::parse(&buf).unwrap();
        assert_eq!(h.flags.rcode, Rcode::NxDomain);
    }

    #[test]
    fn test_header_too_short() {
        assert!(DnsHeader::parse(&[0, 1, 2]).is_none());
    }
}
