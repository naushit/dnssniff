//! Bounded Circular Ring Buffers (`dnssniff-core::ring`)
//!
//! Fixed-capacity ring buffers for live and error transaction streams.
//! Uses inline 64-byte domain storage with an optional 64 KB extended arena
//! for full domain names needed by Server-Sent Events.

use crate::types::TransactionSummary;
use std::sync::atomic::{AtomicU64, Ordering};

/// A fixed-capacity circular ring buffer for `TransactionSummary` records.
///
/// When full, new entries overwrite the oldest (overwrite policy).
pub struct CircularRingBuffer<const N: usize> {
    buffer: [TransactionSummary; N],
    head: AtomicU64, // write position (monotonically increasing)
    count: AtomicU64, // number of valid entries
}

impl<const N: usize> CircularRingBuffer<N> {
    pub fn new() -> Self {
        Self {
            buffer: [TransactionSummary::default(); N],
            head: AtomicU64::new(0),
            count: AtomicU64::new(0),
        }
    }

    /// Push a transaction into the ring. Overwrites oldest if full.
    pub fn push(&mut self, item: TransactionSummary) {
        let idx = (self.head.fetch_add(1, Ordering::Relaxed) % N as u64) as usize;
        let current_count = self.count.fetch_add(1, Ordering::Relaxed);
        if current_count < N as u64 {
            // Still filling up
        }
        self.buffer[idx] = item;
    }

    /// Get the number of valid entries (capped at N).
    pub fn len(&self) -> usize {
        let c = self.count.load(Ordering::Relaxed);
        if c > N as u64 { N } else { c as usize }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Iterate over all valid entries from oldest to newest.
    pub fn iter(&self) -> RingIter<'_, N> {
        let count = self.len();
        let head = self.head.load(Ordering::Relaxed) as usize;
        let start = if count >= N {
            head % N
        } else {
            0
        };
        RingIter {
            buffer: &self.buffer,
            start,
            position: 0,
            remaining: count,
            n: N,
        }
    }

    /// Get a snapshot of all entries as a Vec (for /export.json).
    pub fn snapshot(&self) -> Vec<TransactionSummary> {
        self.iter().collect()
    }
}

impl<const N: usize> Default for CircularRingBuffer<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// Iterator over ring buffer entries from oldest to newest.
pub struct RingIter<'a, const N: usize> {
    buffer: &'a [TransactionSummary; N],
    start: usize,
    position: usize,
    remaining: usize,
    n: usize,
}

impl<'a, const N: usize> Iterator for RingIter<'a, N> {
    type Item = TransactionSummary;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let idx = (self.start + self.position) % self.n;
        self.position += 1;
        self.remaining -= 1;
        Some(self.buffer[idx])
    }
}

/// Extended domain name arena for storing full domain names (up to 253 bytes)
/// that don't fit in the inline 64-byte buffer.
pub struct DomainArena {
    buffer: [u8; crate::types::MAX_INLINE_DOMAIN_LEN * 1024], // 64 KB
    write_pos: AtomicU64,
}

impl DomainArena {
    pub fn new() -> Self {
        Self {
            buffer: [0; 64 * 1024],
            write_pos: AtomicU64::new(0),
        }
    }

    /// Store a domain name string in the arena. Returns an offset into the arena.
    /// The caller is responsible for ensuring the offset remains valid.
    pub fn store(&mut self, domain: &str) -> Option<u32> {
        let bytes = domain.as_bytes();
        if bytes.len() > 255 {
            return None;
        }
        let pos = self.write_pos.fetch_add(bytes.len() as u64 + 1, Ordering::Relaxed);
        if pos + bytes.len() as u64 + 1 > self.buffer.len() as u64 {
            return None;
        }
        self.buffer[pos as usize] = bytes.len() as u8;
        self.buffer[(pos as usize + 1)..(pos as usize + 1 + bytes.len())].copy_from_slice(bytes);
        Some(pos as u32)
    }
}

impl Default for DomainArena {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn make_summary(idx: u64) -> TransactionSummary {
        TransactionSummary {
            timestamp_ms: idx * 1000,
            rtt_us: idx as u32 * 100,
            client_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
            server_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            client_port: 12345,
            server_port: 53,
            transaction_id: idx as u16,
            qtype: 1,
            rcode: 0,
            status: TransactionStatus::Ok,
            domain_name: [0; 48],
            domain_len: 0,
            ifindex: 1,
            raw_packet: [0; 128],
            raw_packet_len: 0,
            direction: 0,
        }
    }

    #[test]
    fn test_ring_push_and_iter() {
        let mut ring: CircularRingBuffer<4> = CircularRingBuffer::new();
        ring.push(make_summary(1));
        ring.push(make_summary(2));
        ring.push(make_summary(3));

        assert_eq!(ring.len(), 3);
        let entries: Vec<_> = ring.iter().collect();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].timestamp_ms, 1000);
        assert_eq!(entries[2].timestamp_ms, 3000);
    }

    #[test]
    fn test_ring_overwrite() {
        let mut ring: CircularRingBuffer<3> = CircularRingBuffer::new();
        for i in 1..=5 {
            ring.push(make_summary(i));
        }
        // Capacity is 3, so only the last 3 should remain
        assert_eq!(ring.len(), 3);
        let entries: Vec<_> = ring.iter().collect();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].timestamp_ms, 3000); // oldest remaining
        assert_eq!(entries[2].timestamp_ms, 5000); // newest
    }

    #[test]
    fn test_domain_arena() {
        let mut arena = DomainArena::new();
        let offset = arena.store("example.com").unwrap();
        assert!(offset < u32::MAX);
        let offset2 = arena.store("a-very-long-domain-name-that-exceeds-64-bytes-and-should-go-into-the-arena.example.com").unwrap();
        assert!(offset2 > offset);
    }
}
