//! Shared telemetry types used across core modules.

use std::net::{IpAddr, Ipv4Addr};

/// Maximum domain name length that fits in the inline buffer.
pub const MAX_INLINE_DOMAIN_LEN: usize = 64;

/// Status of a DNS transaction as observed by the sniffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TransactionStatus {
    /// Query sent, awaiting response (in-flight)
    Pending = 0,
    /// Response received successfully
    Ok = 1,
    /// Query timed out without response
    TimeoutNoResponse = 2,
    /// Malformed or truncated DNS packet
    Malformed = 3,
    /// NXDOMAIN response (RCODE=3)
    NxDomain = 4,
    /// SERVFAIL response (RCODE=2)
    ServFail = 5,
    /// Refused response (RCODE=5)
    Refused = 6,
    /// Truncated response (TC bit set)
    Truncated = 7,
}

impl TransactionStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            TransactionStatus::Pending => "PENDING",
            TransactionStatus::Ok => "OK",
            TransactionStatus::TimeoutNoResponse => "TIMEOUT_NO_RESPONSE",
            TransactionStatus::Malformed => "MALFORMED",
            TransactionStatus::NxDomain => "NXDOMAIN",
            TransactionStatus::ServFail => "SERVFAIL",
            TransactionStatus::Refused => "REFUSED",
            TransactionStatus::Truncated => "TRUNCATED",
        }
    }
}

/// A compact, fixed-size record of a completed DNS transaction.
/// Stored in bounded circular ring buffers.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct TransactionSummary {
    /// Monotonic timestamp in milliseconds since epoch.
    pub timestamp_ms: u64,
    /// Round-trip latency in microseconds (0 for pending/timeout).
    pub rtt_us: u32,
    /// Client source IP address.
    pub client_ip: IpAddr,
    /// Server (DNS resolver) IP address.
    pub server_ip: IpAddr,
    /// Client source port.
    pub client_port: u16,
    /// Server (DNS resolver) port.
    pub server_port: u16,
    /// DNS 16-bit Transaction ID.
    pub transaction_id: u16,
    /// DNS QTYPE (e.g., 1 for A, 28 for AAAA).
    pub qtype: u16,
    /// DNS RCODE from response (0 for NOERROR).
    pub rcode: u8,
    /// Transaction status.
    pub status: TransactionStatus,
    /// Inline dot-delimited ASCII domain name (64 bytes max).
    pub domain_name: [u8; 64],
    /// Length of valid bytes in `domain_name`.
    pub domain_len: u8,
    /// Interface index where the packet was captured.
    pub ifindex: i32,
    /// Raw packet bytes (first 256 bytes) for full packet inspection.
    pub raw_packet: [u8; 256],
    /// Number of valid bytes in `raw_packet`.
    pub raw_packet_len: u16,
    /// Direction: 0 = query (client -> server), 1 = response (server -> client).
    pub direction: u8,
}

impl Default for TransactionSummary {
    fn default() -> Self {
        Self {
            timestamp_ms: 0,
            rtt_us: 0,
            client_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            server_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            client_port: 0,
            server_port: 0,
            transaction_id: 0,
            qtype: 0,
            rcode: 0,
            status: TransactionStatus::Pending,
            domain_name: [0; 64],
            domain_len: 0,
            ifindex: 0,
            raw_packet: [0; 256],
            raw_packet_len: 0,
            direction: 0,
        }
    }
}

/// Correlation key for matching DNS queries and responses.
/// Combines the 5-tuple, Transaction ID, and interface index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TransactionKey {
    pub client_ip: IpAddr,
    pub client_port: u16,
    pub server_ip: IpAddr,
    pub server_port: u16,
    pub transaction_id: u16,
    pub ifindex: i32,
}

impl TransactionKey {
    pub fn new(
        client_ip: IpAddr,
        client_port: u16,
        server_ip: IpAddr,
        server_port: u16,
        transaction_id: u16,
        ifindex: i32,
    ) -> Self {
        Self {
            client_ip,
            client_port,
            server_ip,
            server_port,
            transaction_id,
            ifindex,
        }
    }
}

/// Counters exposed via the /stats JSON endpoint.
#[derive(Debug, Default, Clone)]
pub struct TelemetryCounters {
    pub uptime_secs: u64,
    pub active_queries: u32,
    pub total_queries: u64,
    pub total_responses: u64,
    pub parsed_packets: u64,
    pub unparsed_packets: u64,
    pub timeouts: u64,
    pub servfail: u64,
    pub nxdomain: u64,
    pub refused: u64,
    pub malformed: u64,
    pub table_overflow_evictions: u64,
    pub sse_dropped_events: u64,
}

/// Latency histogram data (64 logarithmic buckets, 100 µs to 10 s).
#[derive(Debug, Clone)]
pub struct LatencyHistogram {
    /// 64 buckets covering 100 µs to 10 s.
    pub buckets: [u64; 64],
    pub count: u64,
    pub sum_us: u64,
}

impl Default for LatencyHistogram {
    fn default() -> Self {
        Self {
            buckets: [0; 64],
            count: 0,
            sum_us: 0,
        }
    }
}

impl LatencyHistogram {
    /// Insert a latency value in microseconds.
    pub fn insert(&mut self, rtt_us: u32) {
        let bucket = Self::bucket_index(rtt_us as u64);
        self.buckets[bucket] += 1;
        self.count += 1;
        self.sum_us += rtt_us as u64;
    }

    /// Compute logarithmic bucket index for a latency in microseconds.
    /// Range: 100 µs to 10 s (10,000,000 µs) across 64 buckets.
    ///
    /// Uses integer math only: 2^17 ≈ 100_000, so each bucket spans
    /// a factor of ~2^(17/63) ≈ 1.22x.  Bucket i covers roughly
    /// [100 * 2^(i*17/63), 100 * 2^((i+1)*17/63)).
    fn bucket_index(latency_us: u64) -> usize {
        if latency_us <= 100 {
            return 0;
        }
        if latency_us >= 10_000_000 {
            return 63;
        }
        // Integer-only log2 scale: log2(latency / 100) / log2(100000) * 63
        // 100000 ≈ 2^17, so log2(x) ≈ (31 - leading_zeros(x)) + fraction.
        // We use (31 - lz((latency_us/100))) * 63 / 17 to bucket.
        let r = (latency_us / 100) as u32;
        ((31 - r.leading_zeros()) as u64 * 63 / 17) as usize
    }

    /// Compute percentile (p50, p90, p99) latency in microseconds.
    pub fn percentile(&self, p: f64) -> u64 {
        if self.count == 0 {
            return 0;
        }
        let target = (self.count as f64 * p) as u64;
        let mut cum: u64 = 0;
        for (i, &count) in self.buckets.iter().enumerate() {
            cum += count;
            if cum >= target {
                // Approximate bucket center using integer math
                let low = if i == 0 {
                    100
                } else {
                    100u64.saturating_mul(2u64.pow(((i as u64) * 17 / 63) as u32))
                };
                let high = if i == 63 {
                    10_000_000
                } else {
                    100u64.saturating_mul(2u64.pow((((i + 1) as u64) * 17 / 63) as u32))
                };
                return low + (high - low) / 2;
            }
        }
        10_000_000
    }

    pub fn avg_us(&self) -> u64 {
        if self.count == 0 {
            return 0;
        }
        self.sum_us / self.count
    }
}

/// JSON-serializable view of telemetry for the /stats endpoint.
#[derive(Debug, Clone)]
pub struct StatsPayload {
    pub uptime_secs: u64,
    pub active_queries: u32,
    pub total_queries: u64,
    pub total_responses: u64,
    pub parsed_packets: u64,
    pub unparsed_packets: u64,
    pub timeouts: u64,
    pub servfail: u64,
    pub nxdomain: u64,
    pub refused: u64,
    pub malformed: u64,
    pub p50_us: u64,
    pub p90_us: u64,
    pub p99_us: u64,
    pub avg_us: u64,
}

/// Escape a string for safe inclusion in a JSON string value.
/// Escapes backslash, double quote, and all control characters (0x00-0x1F).
pub fn escape_json(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str("\\u00");
                out.push_str(&format!("{:02x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}
