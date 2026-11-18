//! Network & Transport Layer Decoder (`dnssniff-core::net_proto`)
//!
//! Parses IPv4/IPv6 and UDP headers on borrowed byte slices (zero allocation).
//! Extracts the 5-tuple and computes the offset where the DNS wire payload begins.

use crate::types::TransactionKey;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Result of parsing network + transport headers.
#[derive(Debug, Clone)]
pub struct ParsedPacket {
    pub client_ip: IpAddr,
    pub server_ip: IpAddr,
    pub client_port: u16,
    pub server_port: u16,
    pub ifindex: i32,
    /// Offset into the buffer where the DNS payload begins.
    pub dns_offset: usize,
    /// Total length of the DNS payload.
    pub dns_len: usize,
    /// IP version (4 or 6).
    pub ip_version: u8,
}

/// Parse an IP + UDP packet from a raw buffer.
///
/// Returns `None` if the packet is not IPv4/IPv6 UDP, or if headers are malformed.
pub fn parse_packet(buf: &[u8], ifindex: i32) -> Option<ParsedPacket> {
    if buf.is_empty() {
        return None;
    }

    let version = buf[0] >> 4;

    match version {
        4 => parse_ipv4_udp(buf, ifindex),
        6 => parse_ipv6_udp(buf, ifindex),
        _ => None,
    }
}

/// Parse IPv4 + UDP headers.
fn parse_ipv4_udp(buf: &[u8], ifindex: i32) -> Option<ParsedPacket> {
    // Minimum IPv4 header is 20 bytes, plus 8 byte UDP header
    if buf.len() < 28 {
        return None;
    }

    let ihl = (buf[0] & 0x0F) as usize * 4;
    if ihl < 20 || ihl > buf.len() {
        return None;
    }

    let protocol = buf[9];
    if protocol != 17 {
        return None; // Not UDP
    }

    let total_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    if total_len > buf.len() || total_len < ihl + 8 {
        return None;
    }

    let client_ip = IpAddr::V4(Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]));
    let server_ip = IpAddr::V4(Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]));

    let udp_offset = ihl;
    if udp_offset + 8 > buf.len() {
        return None;
    }

    let client_port = u16::from_be_bytes([buf[udp_offset], buf[udp_offset + 1]]);
    let server_port = u16::from_be_bytes([buf[udp_offset + 2], buf[udp_offset + 3]]);

    let udp_len = u16::from_be_bytes([buf[udp_offset + 4], buf[udp_offset + 5]]) as usize;
    if udp_len < 8 || udp_offset + udp_len > buf.len() {
        return None;
    }

    let dns_offset = udp_offset + 8;
    let dns_len = udp_len - 8;

    Some(ParsedPacket {
        client_ip,
        server_ip,
        client_port,
        server_port,
        ifindex,
        dns_offset,
        dns_len,
        ip_version: 4,
    })
}

/// Parse IPv6 + UDP headers.
fn parse_ipv6_udp(buf: &[u8], ifindex: i32) -> Option<ParsedPacket> {
    // IPv6 fixed header is 40 bytes, plus 8 byte UDP header
    if buf.len() < 48 {
        return None;
    }

    let next_header = buf[6];
    if next_header != 17 {
        return None; // Not UDP
    }

    let client_ip = IpAddr::V6(Ipv6Addr::from([
        u16::from_be_bytes([buf[8], buf[9]]),
        u16::from_be_bytes([buf[10], buf[11]]),
        u16::from_be_bytes([buf[12], buf[13]]),
        u16::from_be_bytes([buf[14], buf[15]]),
        u16::from_be_bytes([buf[16], buf[17]]),
        u16::from_be_bytes([buf[18], buf[19]]),
        u16::from_be_bytes([buf[20], buf[21]]),
        u16::from_be_bytes([buf[22], buf[23]]),
    ]));
    let server_ip = IpAddr::V6(Ipv6Addr::from([
        u16::from_be_bytes([buf[24], buf[25]]),
        u16::from_be_bytes([buf[26], buf[27]]),
        u16::from_be_bytes([buf[28], buf[29]]),
        u16::from_be_bytes([buf[30], buf[31]]),
        u16::from_be_bytes([buf[32], buf[33]]),
        u16::from_be_bytes([buf[34], buf[35]]),
        u16::from_be_bytes([buf[36], buf[37]]),
        u16::from_be_bytes([buf[38], buf[39]]),
    ]));

    let udp_offset = 40;
    if udp_offset + 8 > buf.len() {
        return None;
    }

    let client_port = u16::from_be_bytes([buf[udp_offset], buf[udp_offset + 1]]);
    let server_port = u16::from_be_bytes([buf[udp_offset + 2], buf[udp_offset + 3]]);

    let udp_len = u16::from_be_bytes([buf[udp_offset + 4], buf[udp_offset + 5]]) as usize;
    if udp_len < 8 || udp_offset + udp_len > buf.len() {
        return None;
    }

    let dns_offset = udp_offset + 8;
    let dns_len = udp_len - 8;

    Some(ParsedPacket {
        client_ip,
        server_ip,
        client_port,
        server_port,
        ifindex,
        dns_offset,
        dns_len,
        ip_version: 6,
    })
}

/// Build a `TransactionKey` from a parsed packet.
pub fn build_key(parsed: &ParsedPacket, transaction_id: u16) -> TransactionKey {
    TransactionKey::new(
        parsed.client_ip,
        parsed.client_port,
        parsed.server_ip,
        parsed.server_port,
        transaction_id,
        parsed.ifindex,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ipv4_udp_dns() -> Vec<u8> {
        // IPv4 (20) + UDP (8) + DNS (12) = 40 bytes
        // net_proto parses from IP header (link-layer stripped by capture)
        let mut buf = Vec::new();
        // IPv4 header
        buf.push(0x45); // version=4, ihl=5
        buf.push(0x00); // DSCP/ECN
        buf.extend_from_slice(&[0x00, 0x28]); // total length = 40 (20 IP + 8 UDP + 12 DNS)
        buf.extend_from_slice(&[0x00, 0x01]); // identification
        buf.extend_from_slice(&[0x00, 0x00]); // flags/fragment
        buf.push(0x40); // TTL
        buf.push(0x11); // protocol = UDP
        buf.extend_from_slice(&[0x00, 0x00]); // header checksum (skip)
        buf.extend_from_slice(&[192, 168, 1, 10]); // client IP
        buf.extend_from_slice(&[8, 8, 8, 8]); // server IP
        // UDP header
        buf.extend_from_slice(&[0x12, 0x34]); // src port = 0x1234
        buf.extend_from_slice(&[0x00, 0x35]); // dst port = 53
        buf.extend_from_slice(&[0x00, 0x14]); // udp length = 20 (8 UDP + 12 DNS)
        buf.extend_from_slice(&[0x00, 0x00]); // checksum
        // DNS header
        buf.extend_from_slice(&[0, 0]); // transaction id
        buf.extend_from_slice(&[0, 0]); // flags
        buf.extend_from_slice(&[0, 0]); // qdcount
        buf.extend_from_slice(&[0, 0]); // ancount
        buf.extend_from_slice(&[0, 0]); // nscount
        buf.extend_from_slice(&[0, 0]); // arcount

        buf
    }

    #[test]
    fn test_parse_ipv4_udp() {
        let buf = make_ipv4_udp_dns();
        // Skip 14-byte Ethernet header; net_proto parses from IP header
        let parsed = parse_packet(&buf, 1).expect("should parse IPv4 UDP");
        assert_eq!(parsed.ip_version, 4);
        assert_eq!(parsed.client_ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)));
        assert_eq!(parsed.server_ip, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        assert_eq!(parsed.client_port, 0x1234);
        assert_eq!(parsed.server_port, 53);
        assert_eq!(parsed.dns_offset, 28); // 20 IP + 8 UDP = 28
        assert_eq!(parsed.ifindex, 1);
    }

    #[test]
    fn test_parse_non_udp() {
        let mut buf = make_ipv4_udp_dns();
        buf[9] = 6; // TCP protocol (IP header offset 9)
        assert!(parse_packet(&buf, 1).is_none());
    }

    #[test]
    fn test_build_key() {
        let buf = make_ipv4_udp_dns();
        let parsed = parse_packet(&buf, 1).unwrap();
        let key = build_key(&parsed, 0xabcd);
        assert_eq!(key.transaction_id, 0xabcd);
        assert_eq!(key.ifindex, 1);
    }
}
