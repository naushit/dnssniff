//! Server-Sent Events Broadcaster (`dnssniff-web::sse`)
//!
//! Streams newline-delimited `data: {...}\n\n` JSON transaction events to
//! connected browser clients over persistent non-blocking HTTP connections
//! with lossy drop policies for slow consumers.

use dnssniff_core::types::TransactionSummary;
use std::collections::VecDeque;
use std::io::{self, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

fn format_transaction_summary_json(t: &TransactionSummary) -> String {
    let domain_len = t.domain_len as usize;
    let domain = if domain_len <= 64 {
        std::str::from_utf8(&t.domain_name[..domain_len]).unwrap_or("")
    } else {
        ""
    };
    format!(
        "{{\"id\":{},\"rtt_us\":{},\"domain\":\"{}\",\"qtype\":{},\"rcode\":{},\"status\":\"{}\",\"client_ip\":\"{}\",\"server_ip\":\"{}\",\"client_port\":{},\"server_port\":{},\"timestamp_ms\":{}}}",
        t.transaction_id,
        t.rtt_us,
        domain,
        t.qtype,
        t.rcode,
        t.status.as_str(),
        t.client_ip,
        t.server_ip,
        t.client_port,
        t.server_port,
        t.timestamp_ms,
    )
}

/// A connected SSE client with a bounded send queue.
pub struct SseClient {
    stream: TcpStream,
    queue: VecDeque<Vec<u8>>,
    last_write: Instant,
    dropped_events: AtomicU64,
}

impl SseClient {
    const MAX_QUEUE: usize = 16;
    const DRAIN_TIMEOUT_SECS: u64 = 1;

    fn new(stream: TcpStream) -> Self {
        Self {
            stream,
            queue: VecDeque::with_capacity(Self::MAX_QUEUE),
            last_write: Instant::now(),
            dropped_events: AtomicU64::new(0),
        }
    }

    /// Try to write an event to the client. Returns false if the client should be dropped.
    fn write_event(&mut self, event: &[u8]) -> io::Result<bool> {
        // Try non-blocking write of queued data first
        self.drain_queue()?;

        // If queue is full, drop this event
        if self.queue.len() >= Self::MAX_QUEUE {
            self.dropped_events.fetch_add(1, Ordering::Relaxed);
            return Ok(true); // keep connection but drop event
        }

        // Try to write directly
        match self.stream.write_all(event) {
            Ok(()) => {
                self.last_write = Instant::now();
                Ok(true)
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                self.queue.push_back(event.to_vec());
                Ok(true)
            }
            Err(_) => Ok(false), // connection broken
        }
    }

    /// Drain the queue to the socket.
    fn drain_queue(&mut self) -> io::Result<()> {
        while let Some(data) = self.queue.front() {
            match self.stream.write_all(data) {
                Ok(()) => {
                    self.queue.pop_front();
                    self.last_write = Instant::now();
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(_) => return Err(io::Error::new(io::ErrorKind::BrokenPipe, "SSE client disconnected")),
            }
        }
        Ok(())
    }

    fn should_disconnect(&self) -> bool {
        self.last_write.elapsed().as_secs() > Self::DRAIN_TIMEOUT_SECS && !self.queue.is_empty()
    }

    fn dropped_count(&self) -> u64 {
        self.dropped_events.load(Ordering::Relaxed)
    }
}

/// Broadcasts SSE events to all connected clients.
pub struct SseBroadcaster {
    clients: Mutex<Vec<Arc<Mutex<SseClient>>>>,
    total_dropped: AtomicU64,
}

impl SseBroadcaster {
    pub fn new() -> Self {
        Self {
            clients: Mutex::new(Vec::new()),
            total_dropped: AtomicU64::new(0),
        }
    }

    /// Accept a new SSE client connection.
    pub fn add_client(&self, stream: TcpStream) -> Arc<Mutex<SseClient>> {
        let client = Arc::new(Mutex::new(SseClient::new(stream)));
        self.clients.lock().unwrap().push(client.clone());
        client
    }

    /// Broadcast an event to all connected clients.
    /// Removes disconnected clients.
    pub fn broadcast(&self, event: &TransactionSummary) {
        let json = format_transaction_summary_json(event);
        let event_str = format!("data: {}\n\n", json);
        let event_bytes = event_str.as_bytes();

        let mut clients = self.clients.lock().unwrap();
        clients.retain(|c| {
            let mut client = c.lock().unwrap();
            match client.write_event(event_bytes) {
                Ok(true) => !client.should_disconnect(),
                Ok(false) => false,
                Err(_) => false,
            }
        });

        // Count dropped events
        for c in clients.iter() {
            let client = c.lock().unwrap();
            let dropped = client.dropped_count();
            if dropped > 0 {
                self.total_dropped.fetch_add(dropped, Ordering::Relaxed);
                // Reset client counter (we already counted it)
                drop(client);
                let client = c.lock().unwrap();
                client.dropped_events.store(0, Ordering::Relaxed);
            }
        }
    }

    /// Get total dropped events across all clients.
    pub fn dropped_count(&self) -> u64 {
        self.total_dropped.load(Ordering::Relaxed)
    }

    /// Number of connected clients.
    pub fn client_count(&self) -> usize {
        self.clients.lock().unwrap().len()
    }
}

impl Default for SseBroadcaster {
    fn default() -> Self {
        Self::new()
    }
}
