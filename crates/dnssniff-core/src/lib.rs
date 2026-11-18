//! # dnssniff-core
//!
//! Core library for `dnssniff`: a lightweight, zero-persistence DNS packet sniffer
//! for embedded Linux / OpenWrt.
//!
//! Provides:
//! - Raw AF_PACKET socket capture with in-kernel cBPF filtering
//! - IPv4/IPv6 + UDP header decoding on borrowed slices (zero alloc)
//! - RFC 1035 DNS wire parser with compression-pointer safety
//! - Bounded in-flight transaction tracker with lazy timeout eviction
//! - Circular ring buffers for live and error transaction streams

pub mod capture;
pub mod dns_proto;
pub mod net_proto;
pub mod ring;
pub mod tracker;

pub mod types;

/// Shared maximum RSS ceiling in bytes (32 MB)
pub const MEMORY_CEILING_BYTES: usize = 32 * 1024 * 1024;

/// Default transaction timeout in seconds (3.0s)
pub const DEFAULT_TIMEOUT_SECS: u64 = 3;

/// Size of the ingress stack buffer (4 KB)
pub const INGRESS_BUF_SIZE: usize = 4096;

/// Capacity of the in-flight tracker hash table
pub const TRACKER_CAPACITY: usize = 8192;

/// Capacity of each ring buffer
pub const RING_CAPACITY: usize = 1000;

/// Size of the domain name arena (64 KB)
pub const DOMAIN_ARENA_SIZE: usize = 64 * 1024;
