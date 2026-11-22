//! # dnssniff-web
//!
//! Portable, decoupled HTTP & Server-Sent Events (SSE) server for DNS telemetry.
//! Designed as a reusable module/crate with clean data-feed traits for use
//! in other DNS-related projects.
//!
//! Endpoints:
//! - `GET /`         - Embedded single-page dashboard
//! - `GET /stats`    - Machine-readable JSON metrics
//! - `GET /events`   - Server-Sent Events stream
//! - `GET /export.json` - Full JSON snapshot
//! - `GET /health`   - Liveness check

pub mod server;
pub mod sse;
pub mod stats_json;

use crate::sse::SseBroadcaster;
use dnssniff_core::types::TelemetryCounters;
use dnssniff_core::ring::CircularRingBuffer;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// Shared application state for the HTTP server.
pub struct AppState {
    pub counters: Arc<Mutex<TelemetryCounters>>,
    pub live_ring: Arc<Mutex<CircularRingBuffer<1000>>>,
    pub error_ring: Arc<Mutex<CircularRingBuffer<1000>>>,
    pub histogram: Arc<Mutex<dnssniff_core::types::LatencyHistogram>>,
    pub sse_broadcaster: Arc<SseBroadcaster>,
    pub uptime_start: AtomicU64,
    pub http_token: Option<String>,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            counters: Arc::new(Mutex::new(TelemetryCounters::default())),
            live_ring: Arc::new(Mutex::new(CircularRingBuffer::new())),
            error_ring: Arc::new(Mutex::new(CircularRingBuffer::new())),
            histogram: Arc::new(Mutex::new(dnssniff_core::types::LatencyHistogram::default())),
            sse_broadcaster: Arc::new(SseBroadcaster::new()),
            http_token: None,
            uptime_start: AtomicU64::new(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            ),
        }
    }

    pub fn uptime_secs(&self) -> u64 {
        let start = self.uptime_start.load(Ordering::Relaxed);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now.saturating_sub(start)
    }

    /// Clone the inner ring buffers for sharing with the capture thread.
    pub fn ring_handles(&self) -> (Arc<Mutex<CircularRingBuffer<1000>>>, Arc<Mutex<CircularRingBuffer<1000>>>) {
        (Arc::clone(&self.live_ring), Arc::clone(&self.error_ring))
    }
}
