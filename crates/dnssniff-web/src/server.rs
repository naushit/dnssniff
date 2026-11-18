//! Non-Blocking HTTP Reactor (`dnssniff-web::server`)
//!
//! Built on `std::net::TcpListener` with non-blocking I/O using
//! `libc::poll` for the event loop. Uses `httparse` for HTTP request parsing.
//!
//! Endpoints:
//! - GET /        - Embedded HTML/JS/CSS dashboard
//! - GET /stats   - Machine-readable JSON metrics
//! - GET /events  - Server-Sent Events stream
//! - GET /export.json - Full JSON snapshot
//! - GET /health  - Liveness check

use crate::stats_json::{compute_stats, format_stats_json};
use crate::AppState;
use dnssniff_core::types::{TelemetryCounters, TransactionSummary};
use httparse;
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream, SocketAddr};
use std::os::unix::io::AsRawFd;
use std::sync::Arc;
const MAX_CLIENTS: usize = 64;

/// Embedded HTML dashboard (compiled into the binary).
const DASHBOARD_HTML: &str = include_str!("../assets/index.html");

/// Run the HTTP server event loop.
/// This function blocks forever, serving HTTP requests on the given address.
pub fn run(
    addr: SocketAddr,
    state: Arc<AppState>,
) -> io::Result<()> {
    let listener = TcpListener::bind(&addr)?;
    listener.set_nonblocking(true)?;

    println!("dnssniff-web: listening on {}", addr);

    let mut connections: HashMap<i32, Connection> = HashMap::new();

    loop {
        // Build pollfd set
        let mut fds: Vec<libc::pollfd> = Vec::new();
        fds.push(libc::pollfd {
            fd: listener.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        });

        for (fd, conn) in connections.iter() {
            let mut events = libc::POLLIN;
            if !conn.write_buf.is_empty() || conn.is_sse {
                events |= libc::POLLOUT;
            }
            fds.push(libc::pollfd {
                fd: *fd,
                events,
                revents: 0,
            });
        }

        let timeout_ms = 100i32;
        let ret = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as _, timeout_ms) };

        if ret < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(io::Error::last_os_error());
        }

        // Check listener for new connections
        if fds[0].revents & libc::POLLIN != 0 {
            loop {
                match listener.accept() {
                    Ok((stream, _peer_addr)) => {
                        stream.set_nonblocking(true)?;
                        let fd = stream.as_raw_fd();
                        if connections.len() >= MAX_CLIENTS {
                            // Too many connections, drop
                            drop(stream);
                            continue;
                        }
                        let conn = Connection::new(stream, Arc::clone(&state));
                        connections.insert(fd, conn);
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) => return Err(e),
                }
            }
        }

        // Handle existing connections
        let mut to_remove: Vec<i32> = Vec::new();

        for i in 1..fds.len() {
            let fd = fds[i].fd;
            let revents = fds[i].revents;

            if revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
                to_remove.push(fd);
                continue;
            }

            if let Some(conn) = connections.get_mut(&fd) {
                let mut done = false;

                if revents & libc::POLLIN != 0 && !conn.request_parsed {
                    match conn.read_request()? {
                        ReadResult::Complete => {
                            // Request already handled in read_request
                        }
                        ReadResult::Incomplete => {}
                        ReadResult::Closed => {
                            done = true;
                        }
                    }
                }

                if !done && conn.is_sse {
                    // SSE connections stay open; broadcaster handles pushing data
                }

                if !done && !conn.write_buf.is_empty() && !conn.is_sse {
                    conn.write_response()?;
                }

                if done || (conn.close_after_write && conn.write_buf.is_empty()) {
                    to_remove.push(fd);
                }
            }
        }

        for fd in to_remove {
            connections.remove(&fd);
        }
    }
}

/// A single HTTP connection state machine.
struct Connection {
    stream: TcpStream,
    state: Arc<AppState>,
    read_buf: [u8; 4096],
    read_len: usize,
    write_buf: Vec<u8>,
    write_pos: usize,
    request_parsed: bool,
    keep_alive: bool,
    close_after_write: bool,
    is_sse: bool,
}

impl Connection {
    fn new(stream: TcpStream, state: Arc<AppState>) -> Self {
        Self {
            stream,
            state,
            read_buf: [0; 4096],
            read_len: 0,
            write_buf: Vec::new(),
            write_pos: 0,
            request_parsed: false,
            keep_alive: true,
            close_after_write: false,
            is_sse: false,
        }
    }

    /// Read HTTP request data from the socket.
    fn read_request(&mut self) -> io::Result<ReadResult> {
        loop {
            if self.read_len >= self.read_buf.len() {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "Request too large"));
            }
            match self.stream.read(&mut self.read_buf[self.read_len..]) {
                Ok(0) => return Ok(ReadResult::Closed),
                Ok(n) => {
                    self.read_len += n;
                    if n < 4096 {
                        break;
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            }
        }

        if self.read_len > 0 {
            let mut headers = [httparse::EMPTY_HEADER; 16];
            let mut req = httparse::Request::new(&mut headers);
            match req.parse(&self.read_buf[..self.read_len]) {
                Ok(httparse::Status::Complete(_)) => {
                    self.request_parsed = true;
                    let path = req.path.unwrap_or("").to_string();
                    let keep_alive = req.headers.iter().any(|h| {
                        h.name.eq_ignore_ascii_case("connection")
                            && std::str::from_utf8(h.value).unwrap_or("").eq_ignore_ascii_case("keep-alive")
                    });
                    self.keep_alive = keep_alive;
                    drop(req);
                    self.handle_parsed_path(&path)?;
                    Ok(ReadResult::Complete)
                }
                Ok(httparse::Status::Partial) => Ok(ReadResult::Incomplete),
                Err(_) => Err(io::Error::new(io::ErrorKind::InvalidInput, "Invalid HTTP request")),
            }
        } else {
            Ok(ReadResult::Incomplete)
        }
    }

    /// Handle a fully parsed HTTP request.
    fn handle_parsed_path(&mut self, path: &str) -> io::Result<()> {
        match path {
            "/" => self.serve_dashboard(),
            "/stats" => self.serve_stats(),
            "/events" => self.serve_sse(),
            "/export.json" => self.serve_export(),
            "/health" => self.serve_health(),
            _ => self.serve_not_found(),
        }
    }

    #[allow(dead_code)]
    fn handle_parsed_request(&mut self, _req: &httparse::Request) -> io::Result<()> {
        Ok(())
    }

    fn serve_dashboard(&mut self) -> io::Result<()> {
        let content = DASHBOARD_HTML.as_bytes();
        let response = format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Type: text/html\r\n\
             Content-Length: {}\r\n\
             Access-Control-Allow-Origin: http://localhost\r\n\
             Access-Control-Allow-Origin: http://127.0.0.1\r\n\
             Cache-Control: no-cache\r\n\
             Connection: close\r\n\
             \r\n",
            content.len()
        );
        self.write_buf.extend_from_slice(response.as_bytes());
        self.write_buf.extend_from_slice(content);
        self.close_after_write = true;
        Ok(())
    }

    fn serve_stats(&mut self) -> io::Result<()> {
        let counters = self.state.counters.lock().unwrap().clone();
        let counters = TelemetryCounters {
            uptime_secs: self.state.uptime_secs(),
            active_queries: counters.active_queries,
            total_queries: counters.total_queries,
            total_responses: counters.total_responses,
            parsed_packets: counters.parsed_packets,
            unparsed_packets: counters.unparsed_packets,
            timeouts: counters.timeouts,
            servfail: counters.servfail,
            nxdomain: counters.nxdomain,
            refused: counters.refused,
            malformed: counters.malformed,
            table_overflow_evictions: counters.table_overflow_evictions,
            sse_dropped_events: self.state.sse_broadcaster.dropped_count(),
        };
        let histogram = self.state.histogram.lock().unwrap().clone();
        let payload = compute_stats(&counters, &histogram);
        let json = format_stats_json(&payload);
        let json_bytes = json.as_bytes();

        let response = format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             Access-Control-Allow-Origin: http://localhost\r\n\
             Access-Control-Allow-Origin: http://127.0.0.1\r\n\
             Connection: close\r\n\
             \r\n",
            json_bytes.len()
        );
        self.write_buf.extend_from_slice(response.as_bytes());
        self.write_buf.extend_from_slice(json_bytes);
        self.close_after_write = true;
        Ok(())
    }

    fn serve_sse(&mut self) -> io::Result<()> {
        let response = "HTTP/1.1 200 OK\r\n\
             Content-Type: text/event-stream\r\n\
             Cache-Control: no-cache\r\n\
             Connection: keep-alive\r\n\
             Access-Control-Allow-Origin: http://localhost\r\n\
             Access-Control-Allow-Origin: http://127.0.0.1\r\n\
             X-Accel-Buffering: no\r\n\
             \r\n";
        self.write_buf.extend_from_slice(response.as_bytes());
        self.is_sse = true;

        // Register this stream as an SSE client (clone for broadcaster)
        let stream_clone = self.stream.try_clone()?;
        self.state.sse_broadcaster.add_client(stream_clone);

        Ok(())
    }

    fn serve_export(&mut self) -> io::Result<()> {
        let live: Vec<TransactionSummary> = self.state.live_ring.lock().unwrap().iter().collect();
        let error: Vec<TransactionSummary> = self.state.error_ring.lock().unwrap().iter().collect();

        let mut json = String::from("{\"live\":[");
        for (i, t) in live.iter().enumerate() {
            if i > 0 {
                json.push(',');
            }
            json.push_str(&format_transaction_json(t));
        }
        json.push_str("],\"errors\":[");
        for (i, t) in error.iter().enumerate() {
            if i > 0 {
                json.push(',');
            }
            json.push_str(&format_transaction_json(t));
        }
        json.push_str("]}");

        let json_bytes = json.as_bytes();
        let response = format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             Access-Control-Allow-Origin: http://localhost\r\n\
             Connection: close\r\n\
             \r\n",
            json_bytes.len()
        );
        self.write_buf.extend_from_slice(response.as_bytes());
        self.write_buf.extend_from_slice(json_bytes);
        self.close_after_write = true;
        Ok(())
    }

    fn serve_health(&mut self) -> io::Result<()> {
        let body = r#"{"status":"ok"}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             \r\n{}",
            body.len(),
            body
        );
        self.write_buf.extend_from_slice(response.as_bytes());
        self.close_after_write = true;
        Ok(())
    }

    fn serve_not_found(&mut self) -> io::Result<()> {
        let body = "404 Not Found";
        let response = format!(
            "HTTP/1.1 404 Not Found\r\n\
             Content-Type: text/plain\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             \r\n{}",
            body.len(),
            body
        );
        self.write_buf.extend_from_slice(response.as_bytes());
        self.close_after_write = true;
        Ok(())
    }

    /// Write buffered response data to the socket.
    fn write_response(&mut self) -> io::Result<()> {
        while self.write_pos < self.write_buf.len() {
            match self.stream.write(&self.write_buf[self.write_pos..]) {
                Ok(0) => break,
                Ok(n) => self.write_pos += n,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            }
        }
        if self.write_pos >= self.write_buf.len() {
            self.write_buf.clear();
            self.write_pos = 0;
        }
        Ok(())
    }
}

enum ReadResult {
    Complete,
    Incomplete,
    Closed,
}

/// Format a TransactionSummary as JSON.
fn format_transaction_json(t: &TransactionSummary) -> String {
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
        domain.replace('"', "\\\""),
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
