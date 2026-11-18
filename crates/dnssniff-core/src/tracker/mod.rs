//! In-Flight Transaction Tracker (`dnssniff-core::tracker`)
//!
//! Matches DNS queries and responses using 5-tuple + Transaction ID.
//! Bounded hash table with generation-indexed lazy FIFO timeout eviction.

use crate::types::*;
use crate::{DEFAULT_TIMEOUT_SECS, TRACKER_CAPACITY};
use std::collections::VecDeque;
use std::time::Instant;

/// Configuration for the tracker.
#[derive(Debug, Clone)]
pub struct TrackerConfig {
    pub timeout_secs: u64,
    pub capacity: usize,
}

impl Default for TrackerConfig {
    fn default() -> Self {
        Self {
            timeout_secs: DEFAULT_TIMEOUT_SECS,
            capacity: TRACKER_CAPACITY,
        }
    }
}

/// A slot in the tracker's fixed-capacity table.
#[derive(Debug, Clone)]
struct TrackerSlot {
    /// The key for this slot (when occupied).
    key: Option<TransactionKey>,
    /// Monotonic generation number for ABA prevention.
    generation: u64,
    /// Timestamp when the query was recorded.
    query_time: Instant,
    /// Whether this slot has been matched with a response.
    completed: bool,
}

/// The transaction tracker.
pub struct TransactionTracker {
    /// Fixed-capacity slot table.
    slots: Vec<TrackerSlot>,
    /// FIFO queue of (instant, slot_index, generation) for lazy timeout eviction.
    timeout_queue: VecDeque<(Instant, u32, u64)>,
    /// Monotonic generation counter.
    generation_counter: u64,
    /// Configuration.
    config: TrackerConfig,
    /// Count of overflow evictions.
    overflow_evictions: u64,
}

impl TransactionTracker {
    pub fn new(config: TrackerConfig) -> Self {
        Self {
            slots: (0..config.capacity)
                .map(|_| TrackerSlot {
                    key: None,
                    generation: 0,
                    query_time: Instant::now(),
                    completed: false,
                })
                .collect(),
            timeout_queue: VecDeque::with_capacity(config.capacity),
            generation_counter: 0,
            config,
            overflow_evictions: 0,
        }
    }

    /// Register a new query. Returns the assigned slot index.
    /// If the table is full, evicts the oldest pending query.
    pub fn register_query(
        &mut self,
        key: TransactionKey,
        now: Instant,
    ) -> Option<usize> {
        // Find an empty slot or evict the oldest
        let slot_idx = self.find_available_slot();

        let slot_idx = match slot_idx {
            Some(idx) => idx,
            None => {
                // Table full: evict the oldest pending entry from the queue
                self.evict_oldest_pending()?
            }
        };

        // Increment generation for ABA prevention
        self.generation_counter = self.generation_counter.wrapping_add(1);
        let generation = self.generation_counter;

        self.slots[slot_idx] = TrackerSlot {
            key: Some(key),
            generation,
            query_time: now,
            completed: false,
        };

        // Push to timeout queue
        self.timeout_queue.push_back((now, slot_idx as u32, generation));

        Some(slot_idx)
    }

    /// Match a response to a pending query. Returns the matched slot index and
    /// the round-trip time in microseconds, or None if no match found.
    pub fn match_response(
        &mut self,
        key: &TransactionKey,
        now: Instant,
    ) -> Option<(usize, u64)> {
        // Linear scan through slots (bounded by capacity)
        for (i, slot) in self.slots.iter().enumerate() {
            if let Some(slot_key) = &slot.key {
                if *slot_key == *key && !slot.completed {
                    let rtt_us = now.duration_since(slot.query_time).as_micros() as u64;
                    // Mark as completed (generation stays the same for ABA check)
                    // We don't mutate here because of borrow checker; use a two-pass approach
                    return Some((i, rtt_us));
                }
            }
        }
        None
    }

    /// Mark a matched slot as completed.
    pub fn mark_completed(&mut self, slot_idx: usize) {
        if let Some(slot) = self.slots.get_mut(slot_idx) {
            slot.completed = true;
        }
    }

    /// Sweep expired queries. Returns a list of (slot_index, key) for timed-out queries.
    pub fn sweep_timeouts(&mut self, _now: Instant) -> Vec<(usize, TransactionKey)> {
        let mut expired = Vec::new();
        let timeout_duration = std::time::Duration::from_secs(self.config.timeout_secs);

        while let Some((queue_time, slot_idx, generation)) = self.timeout_queue.front() {
            let slot_idx = *slot_idx as usize;

            // Check if this queue entry is still valid (generation matches)
            let slot_valid = self.slots.get(slot_idx).map_or(false, |s| {
                s.key.is_some() && s.generation == *generation && !s.completed
            });

            if !slot_valid {
                // Stale entry (slot was recycled or completed), discard
                self.timeout_queue.pop_front();
                continue;
            }

            let slot = &self.slots[slot_idx];
            if queue_time.elapsed() >= timeout_duration {
                // This query has timed out
                let key = slot.key.unwrap();
                expired.push((slot_idx, key));
                self.timeout_queue.pop_front();
            } else {
                // Queue is time-ordered, so we can stop
                break;
            }
        }

        expired
    }

    /// Expire specific slots (e.g., after marking them as timed out).
    pub fn expire_slots(&mut self, slots: &[(usize, TransactionKey)]) {
        for (slot_idx, _) in slots {
            if let Some(slot) = self.slots.get_mut(*slot_idx) {
                slot.key = None;
                slot.completed = true;
            }
        }
    }

    /// Get the count of active (pending, non-completed) queries.
    pub fn active_count(&self) -> u32 {
        self.slots.iter().filter(|s| s.key.is_some() && !s.completed).count() as u32
    }

    /// Get overflow eviction count.
    pub fn overflow_evictions(&self) -> u64 {
        self.overflow_evictions
    }

    fn find_available_slot(&mut self) -> Option<usize> {
        for (i, slot) in self.slots.iter().enumerate() {
            if slot.key.is_none() || slot.completed {
                return Some(i);
            }
        }
        None
    }

    fn evict_oldest_pending(&mut self) -> Option<usize> {
        // Evict from the timeout queue front (oldest pending)
        while let Some((_, slot_idx, generation)) = self.timeout_queue.pop_front() {
            let slot_idx = slot_idx as usize;
            if let Some(slot) = self.slots.get_mut(slot_idx) {
                if slot.key.is_some() && slot.generation == generation && !slot.completed {
                    // Evict this slot
                    slot.key = None;
                    slot.completed = true;
                    self.overflow_evictions += 1;
                    return Some(slot_idx);
                }
                // Stale entry, continue searching
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::{Duration, Instant};

    fn make_key(ifindex: i32, tid: u16) -> TransactionKey {
        TransactionKey::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
            12345,
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            53,
            tid,
            ifindex,
        )
    }

    #[test]
    fn test_register_and_match() {
        let mut tracker = TransactionTracker::new(TrackerConfig::default());
        let key = make_key(1, 0x1234);
        let now = Instant::now();

        let slot = tracker.register_query(key, now).unwrap();
        assert!(tracker.active_count() == 1);

        let result = tracker.match_response(&key, now);
        assert!(result.is_some());
        let (slot_idx, _rtt_us) = result.unwrap();
        assert_eq!(slot_idx, slot);
        tracker.mark_completed(slot_idx);
        assert!(tracker.active_count() == 0);
    }

    #[test]
    fn test_timeout_eviction() {
        let mut tracker = TransactionTracker::new(TrackerConfig {
            timeout_secs: 1,
            capacity: 8192,
        });
        let key = make_key(1, 0x9999);
        let old = Instant::now() - Duration::from_secs(5);

        tracker.register_query(key, old);
        assert_eq!(tracker.active_count(), 1);

        let now = Instant::now();
        let expired = tracker.sweep_timeouts(now);
        assert_eq!(expired.len(), 1);
        tracker.expire_slots(&expired);
        assert_eq!(tracker.active_count(), 0);
    }

    #[test]
    fn test_no_false_timeout() {
        let mut tracker = TransactionTracker::new(TrackerConfig {
            timeout_secs: 10,
            capacity: 8192,
        });
        let key = make_key(1, 0xabcd);
        let now = Instant::now();

        tracker.register_query(key, now);
        assert_eq!(tracker.sweep_timeouts(now).len(), 0);
    }

    #[test]
    fn test_generation_aba_prevention() {
        let mut tracker = TransactionTracker::new(TrackerConfig {
            timeout_secs: 1,
            capacity: 2,
        });

        let now = Instant::now();
        let key1 = make_key(1, 0x0001);
        let key2 = make_key(1, 0x0002);

        // Fill the table
        let slot1 = tracker.register_query(key1, now).unwrap();
        let slot2 = tracker.register_query(key2, now).unwrap();
        assert_eq!(slot1, 0);
        assert_eq!(slot2, 1);

        // Now register a third - should evict the oldest
        let key3 = make_key(1, 0x0003);
        let _slot3 = tracker.register_query(key3, now).unwrap();

        // First key should have been evicted
        assert!(tracker.match_response(&key1, now).is_none());
    }
}
