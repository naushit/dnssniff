//! DNS Protocol Module (`dnssniff-core::dns_proto`)
//!
//! Safe zero-allocation RFC 1035 wire-format parser operating on borrowed slices.
//! Enforces strict compression-pointer bounds to prevent DoS via recursive pointers.

pub mod header;
pub mod parser;

pub use header::{DnsHeader, DnsFlags, Rcode, Opcode};
pub use parser::{parse_dns_message, DnsQuestion, ParsedDnsMessage};

/// Maximum DNS compression pointer hops to prevent DoS loops.
pub const MAX_COMPRESSION_HOPS: u8 = 16;
