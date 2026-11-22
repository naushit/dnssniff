//! Server-Sent Events Broadcaster (`dnssniff-web::sse`)
//!
//! Streams newline-delimited `data: {...}\n\n` JSON transaction events to
//! connected browser clients over persistent non-blocking HTTP connections
//! with lossy drop policies for slow consumers.

use dnssniff_core::types::{escape_json, TransactionSummary};
use std::collections::VecDeque;
use std::io::{self, Write};
use std::net::TcpStream;
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// Maximum number of concurrent SSE clients (separate from total connections).
pub const MAX_SSE_CLIENTS: usize = 32;

fn format_transaction_summary_json(t: &TransactionSummary) -> String {
    let domain_len = t.domain_len as usize;
    let domain = if domain_len <= 64 {
        std::str::from_utf8(&t.domain_name[..domain_len]).unwrap_or("")
    } else {
        ""
    };
    let raw_len = t.raw_packet_len as usize;
    let raw_hex: String = t.raw_packet[..raw_len.min(256)]
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();
    format!(
        "{{\"direction\":{},\"transaction_id\":{},\"rtt_us\":{},\"domain\":\"{}\",\"qtype\":{},\"rcode\":{},\"status\":\"{}\",\"client_ip\":\"{}\",\"server_ip\":\"{}\",\"client_port\":{},\"server_port\":{},\"timestamp_ms\":{},\"raw_hex\":\"{}\",\"raw_len\":{}}}",
        t.direction,
        t.transaction_id,
        t.rtt_us,
        escape_json(domain),
        t.qtype,
        t.rcode,
        t.status.as_str(),
        t.client_ip,
        t.server_ip,
        t.client_port,
        t.server_port,
        t.timestamp_ms,
        escape_json(&raw_hex),
        raw_len,
    )
}

/// A connected SSE client with a bounded send queue.
pub struct SseClient {
    stream: TcpStream,
    fd: i32,
    queue: VecDeque<Vec<u8>>,
    write_offset: usize,
    last_write: Instant,
    dropped_events: AtomicU64,
}

impl SseClient {
    const MAX_QUEUE: usize = 16;
    const DRAIN_TIMEOUT_SECS: u64 = 1;

    fn new(stream: TcpStream) -> Self {
        let fd = stream.as_raw_fd();
        Self {
            stream,
            fd,
            queue: VecDeque::with_capacity(Self::MAX_QUEUE),
            write_offset: 0,
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

        // Try to write directly (use write, not write_all, to handle partial writes)
        match self.stream.write(event) {
            Ok(0) => {
                // Socket would block or wrote nothing; queue the full event
                self.queue.push_back(event.to_vec());
                Ok(true)
            }
            Ok(n) if n < event.len() => {
                // Partial write: keep remaining bytes for next attempt
                self.queue.push_back(event[n..].to_vec());
                self.last_write = Instant::now();
                Ok(true)
            }
            Ok(_) => {
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

    /// Drain the queue to the socket, tracking write offset for partial writes.
    fn drain_queue(&mut self) -> io::Result<()> {
        while let Some(data) = self.queue.front() {
            match self.stream.write(&data[self.write_offset..]) {
                Ok(0) => break,
                Ok(n) => {
                    self.write_offset += n;
                    if self.write_offset >= data.len() {
                        self.queue.pop_front();
                        self.write_offset = 0;
                        self.last_write = Instant::now();
                    }
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

    /// The raw socket fd, used to identify this client for removal.
    pub fn fd(&self) -> i32 {
        self.fd
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
    /// Returns None if the SSE client limit is reached.
    pub fn add_client(&self, stream: TcpStream) -> Option<Arc<Mutex<SseClient>>> {
        let clients = self.clients.lock().unwrap();
        if clients.len() >= Self::max_sse_clients() {
            return None;
        }
        drop(clients);
        let client = Arc::new(Mutex::new(SseClient::new(stream)));
        self.clients.lock().unwrap().push(client.clone());
        Some(client)
    }

    fn max_sse_clients() -> usize {
        MAX_SSE_CLIENTS
    }

    /// Remove a client by its socket fd. Called when the HTTP connection drops.
    pub fn remove_client(&self, fd: i32) {
        let mut clients = self.clients.lock().unwrap();
        clients.retain(|c| {
            let client = c.lock().unwrap();
            client.fd() != fd
        });
    }

    /// Broadcast an event to all connected clients.
    /// Removes disconnected clients.
    #[allow(dead_code)]
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

    /// Broadcast a raw JSON string event to all connected clients.
    /// Used for combined query+response pair events.
    pub fn broadcast_str(&self, json: &str) {
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
