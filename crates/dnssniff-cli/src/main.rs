//! # dnssniff CLI Daemon
//!
//! Application entrypoint. Parses CLI flags, opens a raw AF_PACKET socket
//! (matching the working test sniffer at ../test/src/main.rs), captures DNS
//! packets via cBPF filter, and serves telemetry over HTTP.

use dnssniff_core::capture::{attach_bpf_filter, dlt};
use dnssniff_core::dns_proto::header::Rcode;
use dnssniff_web::AppState;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use libc::{
    c_int, c_uchar, c_ushort, c_ulong, c_void, socklen_t, AF_PACKET, SIOCGIFINDEX, SOCK_RAW,
    htons,
};

use std::ffi::CString;
use std::io;
use std::io::Write;
use std::mem;
use std::ptr;

const ETH_P_ALL_VAL: c_ushort = 0x0003;

#[repr(C)]
struct sockaddr_ll {
    sll_family: c_ushort,
    sll_protocol: c_ushort,
    sll_ifindex: c_int,
    sll_hatype: c_ushort,
    sll_pkttype: c_uchar,
    sll_halen: c_uchar,
    sll_addr: [c_uchar; 8],
}

/// Full-size ifreq matching kernel sizeof(struct ifreq) (40 bytes on 64-bit).
/// ifr_ifindex at offset 16 matches kernel layout; padding prevents OOB read.
#[repr(C)]
struct ifreq {
    ifr_name: [i8; 16],
    ifr_ifindex: c_int,
    _pad: [u8; 20],
}

/// List network interfaces by reading /proc/net/dev.
/// Returns (name, ifindex) pairs.
fn list_network_interfaces() -> std::io::Result<Vec<(String, i32)>> {
    let content = std::fs::read_to_string("/proc/net/dev")?;
    let mut result = Vec::new();
    for line in content.lines().skip(2) {
        if let Some((name, _rest)) = line.split_once(':') {
            let name = name.trim();
            if name.is_empty() {
                continue;
            }
            let c_name = CString::new(name)
                .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "interface name contains NUL"))?;
            let idx = unsafe { raw_if_nametoindex(c_name.as_ptr()) } as i32;
            if idx > 0 {
                result.push((name.to_string(), idx));
            }
        }
    }
    Ok(result)
}

/// Auto-detect the first non-loopback, non-virtual interface.
fn auto_detect_interface() -> Option<String> {
    let ifs = list_network_interfaces().ok()?;
    let preferred = ifs.iter().find(|(name, _)| name == "eth0" || name.starts_with("en"));
    if let Some((name, _)) = preferred {
        return Some(name.clone());
    }
    let any = ifs.iter().find(|(name, _)| name != "lo" && !name.starts_with("docker") && !name.starts_with("br-") && !name.starts_with("veth"));
    any.map(|(name, _)| name.clone())
}

fn print_usage() {
    println!("dnssniff - Lightweight DNS Sniffer for OpenWrt");
    println!("Usage: dnssniff [OPTIONS]");
    println!("  -i, --interface <iface>  Network interface (br-lan, eth0, or 'any') [default: any]");
    println!("      --timeout <secs>     DNS query timeout in seconds [default: 3]");
    println!("      --http-port <port>   HTTP server listen port [default: 9153]");
    println!("      --http-host <addr>   HTTP server listen address [default: 0.0.0.0]");
    println!("  -h, --help               Show this help message");
    println!("  -v, --verbose            Enable verbose logging");
    println!("      --list-interfaces    List available network interfaces and exit");
}

struct Args {
    interface: String,
    timeout_secs: u64,
    http_port: u16,
    http_host: String,
    verbose: bool,
    list_interfaces: bool,
}

fn parse_args() -> Args {
    let mut interface = String::from("any");
    let mut timeout_secs: u64 = 3;
    let mut http_port: u16 = 9153;
    let mut http_host = String::from("0.0.0.0");
    let mut verbose = false;
    let mut list_interfaces = false;

    let argv: Vec<String> = std::env::args().collect();
    let mut i = 1;
    while i < argv.len() {
        match argv[i].as_str() {
            "-i" | "--interface" => {
                i += 1;
                if i < argv.len() {
                    interface = argv[i].clone();
                }
            }
            "--timeout" => {
                i += 1;
                if i < argv.len() {
                    timeout_secs = argv[i].parse().unwrap_or(3);
                }
            }
            "--http-port" => {
                i += 1;
                if i < argv.len() {
                    http_port = argv[i].parse().unwrap_or(9153);
                }
            }
            "--http-host" => {
                i += 1;
                if i < argv.len() {
                    http_host = argv[i].clone();
                }
            }
            "-h" | "--help" => {
                print_usage();
                std::process::exit(0);
            }
            "-v" | "--verbose" => {
                verbose = true;
            }
            "--list-interfaces" => {
                list_interfaces = true;
            }
            _ => {
                eprintln!("Unknown option: {}", argv[i]);
                print_usage();
                std::process::exit(1);
            }
        }
        i += 1;
    }

    Args {
        interface,
        timeout_secs,
        http_port,
        http_host,
        verbose,
        list_interfaces,
    }
}

/// Pending DNS query waiting for a response.
struct PendingQuery {
    timestamp_ms: u64,
    domain: String,
    qtype: u16,
    client_ip: IpAddr,
    server_ip: IpAddr,
    client_port: u16,
    server_port: u16,
    transaction_id: u16,
    raw_hex: String,
}

/// Escape a string for safe inclusion in a JSON string value.
fn escape_json(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

/// Convert DNS RCODE enum to u8 value.
fn rcode_to_u8(rcode: &dnssniff_core::dns_proto::header::Rcode) -> u8 {
    match rcode {
        dnssniff_core::dns_proto::header::Rcode::NoError => 0,
        dnssniff_core::dns_proto::header::Rcode::FormErr => 1,
        dnssniff_core::dns_proto::header::Rcode::ServFail => 2,
        dnssniff_core::dns_proto::header::Rcode::NxDomain => 3,
        dnssniff_core::dns_proto::header::Rcode::NotImp => 4,
        dnssniff_core::dns_proto::header::Rcode::Refused => 5,
        dnssniff_core::dns_proto::header::Rcode::Other(v) => *v,
        _ => 0,
    }
}

/// Convert DNS RCODE enum to string.
fn rcode_to_str(rcode: &dnssniff_core::dns_proto::header::Rcode) -> &'static str {
    match rcode {
        dnssniff_core::dns_proto::header::Rcode::NoError => "NOERROR",
        dnssniff_core::dns_proto::header::Rcode::FormErr => "FORMERR",
        dnssniff_core::dns_proto::header::Rcode::ServFail => "SERVFAIL",
        dnssniff_core::dns_proto::header::Rcode::NxDomain => "NXDOMAIN",
        dnssniff_core::dns_proto::header::Rcode::NotImp => "NOTIMP",
        dnssniff_core::dns_proto::header::Rcode::Refused => "REFUSED",
        dnssniff_core::dns_proto::header::Rcode::YXDomain => "YXDOMAIN",
        dnssniff_core::dns_proto::header::Rcode::YXRrset => "YXRRSET",
        dnssniff_core::dns_proto::header::Rcode::NXRrset => "NXRRSET",
        dnssniff_core::dns_proto::header::Rcode::NotAuth => "NOTAUTH",
        dnssniff_core::dns_proto::header::Rcode::NotZone => "NOTZONE",
        dnssniff_core::dns_proto::header::Rcode::Other(_) => "OTHER",
    }
}

fn main() {
    // Set panic hook to catch any panics
    std::panic::set_hook(Box::new(|info| {
        eprintln!("PANIC: {}", info);
        std::io::stderr().flush().unwrap();
    }));

    let args = parse_args();

    // Check for root / CAP_NET_RAW
    if unsafe { raw_geteuid() } != 0 {
        eprintln!("WARNING: not running as root. Raw packet capture requires CAP_NET_RAW.");
        eprintln!("         Try: sudo dnssniff ...");
        eprintln!("");
    }

    // Detect WSL2
    if let Ok(osrelease) = std::fs::read_to_string("/proc/sys/kernel/osrelease") {
        if osrelease.to_lowercase().contains("microsoft") || osrelease.contains("WSL2") {
            eprintln!("WARNING: Detected WSL2.");
            eprintln!("         AF_PACKET raw sockets may not capture traffic from Windows applications.");
            eprintln!("         DNS traffic from WSL2 Linux apps should still be visible.");
            eprintln!("");
        }
    }

    println!("dnssniff starting...");
    println!("  Interface: {}", args.interface);
    println!("  Timeout: {}s", args.timeout_secs);
    println!("  HTTP: {}:{}", args.http_host, args.http_port);
    println!("  Verbose: {}", args.verbose);
    println!("  BPF filter: DNS port 53 (always on)");
    std::io::stdout().flush().unwrap();

    // List interfaces and exit if requested
    if args.list_interfaces {
        println!("Available interfaces:");
        if let Ok(ifs) = list_network_interfaces() {
            for (name, idx) in &ifs {
                let is_loopback = name == "lo" || name.starts_with("docker") || name.starts_with("br-");
                let marker = if is_loopback { "  (skip)" } else { "" };
                println!("  {} (ifindex={}){}", name, idx, marker);
            }
        }
        std::process::exit(0);
    }

    // Auto-detect interface when "any" is specified
    let iface_name: Option<String> = if args.interface == "any" {
        match auto_detect_interface() {
            Some(name) => {
                println!("  Auto-detected interface: {}", name);
                std::io::stdout().flush().unwrap();
                Some(name)
            }
            None => {
                eprintln!("WARNING: could not auto-detect interface, binding to all (ifindex=0)");
                None
            }
        }
    } else {
        Some(args.interface.clone())
    };
    let iface = iface_name.as_deref();

    // --- Shared HTTP state ---
    let http_state = Arc::new(AppState::new());

    // Extract handles for the capture thread
    let _live_ring = http_state.live_ring.clone();
    let sse_broadcaster = http_state.sse_broadcaster.clone();

    // Spawn HTTP server thread
    let http_addr: SocketAddr = format!("{}:{}", args.http_host, args.http_port)
        .parse()
        .expect("Invalid HTTP address");
    let http_state_clone = Arc::clone(&http_state);
    std::thread::spawn(move || {
        if let Err(e) = dnssniff_web::server::run(http_addr, http_state_clone) {
            eprintln!("HTTP server error: {}", e);
        }
    });

    // --- Exact same socket setup as the working test sniffer ---

    let iface_c = match iface.map(|s| CString::new(s)) {
        Some(Ok(s)) => s,
        Some(Err(_)) => {
            eprintln!("Invalid interface name (contains NUL byte)");
            std::process::exit(1);
        }
        None => CString::new("").unwrap(),
    };

    let fd = match unsafe { raw_socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL_VAL) as c_int) } {
        Ok(fd) => fd,
        Err(_) => {
            eprintln!("Failed to create raw socket (try running as root)");
            std::process::exit(1);
        }
    };

    let mut ifr = ifreq {
        ifr_name: [0; 16],
        ifr_ifindex: 0,
        _pad: [0; 20],
    };
    let name_bytes = iface_c.as_bytes_with_nul();
    if name_bytes.len() > 16 {
        eprintln!("Interface name too long: {:?}", iface);
        unsafe { raw_close(fd) };
        std::process::exit(1);
    }
    for (i, b) in name_bytes.iter().enumerate() {
        ifr.ifr_name[i] = *b as i8;
    }

    let ifindex = if unsafe { raw_ioctl(fd, SIOCGIFINDEX, &mut ifr as *mut ifreq as *mut c_void) } < 0 {
        eprintln!("Failed to get interface index for '{:?}'", iface);
        unsafe { raw_close(fd) };
        std::process::exit(1);
    } else {
        ifr.ifr_ifindex
    };

    let addr = sockaddr_ll {
        sll_family: AF_PACKET as c_ushort,
        sll_protocol: htons(ETH_P_ALL_VAL),
        sll_ifindex: ifindex,
        sll_hatype: 0,
        sll_pkttype: 0,
        sll_halen: 0,
        sll_addr: [0; 8],
    };

    if unsafe { raw_bind(fd, &addr as *const sockaddr_ll as *const libc::sockaddr, mem::size_of::<sockaddr_ll>() as socklen_t) } < 0 {
        eprintln!("Failed to bind to interface '{:?}'", iface);
        unsafe { raw_close(fd) };
        std::process::exit(1);
    }

    println!("Sniffing on {:?} (ifindex {}) … Press Ctrl-C to stop", iface, ifindex);
    std::io::stdout().flush().unwrap();

    // Attach cBPF filter for DNS traffic (always on)
    // We always bind to a specific interface (auto-detected when "any"),
    // so link type is always Ethernet (EN10MB), never Linux cooked (LINUX_SLL).
    match attach_bpf_filter(fd, dlt::EN10MB) {
        Ok(_) => println!("cBPF filter attached (DLT=EN10MB)"),
        Err(e) => {
            eprintln!("Failed to attach BPF filter: {}", e);
            unsafe { raw_close(fd) };
            std::process::exit(1);
        }
    }

    let mut buf: [u8; 65535] = [0; 65535];
    let mut packets_received: u64 = 0;
    let pending_queries: Arc<Mutex<HashMap<(u16, i32, IpAddr, u16, IpAddr, u16), PendingQuery>>> =
        Arc::new(Mutex::new(HashMap::new()));

    // --- Timeout detection thread ---
    let pending_queries_timeout = Arc::clone(&pending_queries);
    let http_state_timeout = Arc::clone(&http_state);
    let sse_broadcaster_timeout = Arc::clone(&sse_broadcaster);
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(Duration::from_secs(1));
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
            let timeout_ms = 5000;
            let mut pq = pending_queries_timeout.lock().unwrap();
            let expired: Vec<(u16, i32, IpAddr, u16, IpAddr, u16)> = pq
                .iter()
                .filter(|(_, p)| now_ms.saturating_sub(p.timestamp_ms) >= timeout_ms)
                .map(|(k, _)| *k)
                .collect();
            for key in &expired {
                if let Some(p) = pq.remove(key) {
                    let mut counters = http_state_timeout.counters.lock().unwrap();
                    counters.timeouts += 1;
                    drop(counters);
                    let timeout_json = format!(r#"{{"type":"timeout","domain":"{}","qtype":{},"client_ip":"{}","client_port":{},"server_ip":"{}","server_port":{},"transaction_id":{},"timestamp_ms":{}}}"#,
                        escape_json(&p.domain),
                        p.qtype,
                        p.client_ip,
                        p.client_port,
                        p.server_ip,
                        p.server_port,
                        p.transaction_id,
                        p.timestamp_ms
                    );
                    sse_broadcaster_timeout.broadcast_str(&timeout_json);
                }
            }
        }
    });

    loop {
        let n = unsafe { raw_recvfrom(fd, buf.as_mut_ptr() as *mut c_void, buf.len(), 0, ptr::null_mut(), ptr::null_mut()) };
        if n < 0 {
            eprintln!("Error receiving packet");
            break;
        }

            // Parse IP + UDP + DNS headers (skip 14-byte Ethernet header)
            let n = n as usize;
            packets_received += 1;
            if args.verbose {
                println!("packet #{}: {} bytes", packets_received, n);
                std::io::stdout().flush().unwrap();
            }

            let mut counters = http_state.counters.lock().unwrap();

            if n < 14 {
                counters.unparsed_packets += 1;
                continue;
            }
            let ethertype = u16::from_be_bytes([buf[12], buf[13]]);
            if ethertype != 0x0800 && ethertype != 0x86dd {
                counters.unparsed_packets += 1;
                continue; // not IPv4/IPv6
            }

            let parse_result = dnssniff_core::net_proto::parse_packet(&buf[14..n], ifindex);
            let Some(parsed) = parse_result else {
                counters.unparsed_packets += 1;
                continue;
            };

            let dns_buf = &buf[14 + parsed.dns_offset..14 + parsed.dns_offset + parsed.dns_len];
            let dns_result = dnssniff_core::dns_proto::parser::parse_dns_message(dns_buf);
            let Ok(dns_msg) = dns_result else {
                counters.unparsed_packets += 1;
                continue;
            };

            counters.parsed_packets += 1;

            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;

            let tx_id = dns_msg.header.transaction_id;
            let domain = dns_msg.questions.first().map(|q| q.name.as_str()).unwrap_or("");
            let qtype = dns_msg.questions.first().map(|q| q.qtype).unwrap_or(0);
            let ancount = dns_msg.header.ancount;

            // Canonical key for matching query+response (endpoints sorted)
            let ep_a = (parsed.client_ip, parsed.client_port);
            let ep_b = (parsed.server_ip, parsed.server_port);
            let (ep1_ip, ep1_port, ep2_ip, ep2_port) = if ep_a <= ep_b {
                (ep_a.0, ep_a.1, ep_b.0, ep_b.1)
            } else {
                (ep_b.0, ep_b.1, ep_a.0, ep_a.1)
            };
            let pair_key = (tx_id, ifindex, ep1_ip, ep1_port, ep2_ip, ep2_port);

            if dns_msg.header.flags.qr {
                // RESPONSE — try to match with pending query
                if let Some(pending) = pending_queries.lock().unwrap().remove(&pair_key) {
                    let rtt_us = now_ms.saturating_sub(pending.timestamp_ms);

                    // Build combined pair JSON for SSE
                    let response_raw_hex: String = buf[..n.min(256)]
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect();

                let pair_json = format!(r#"{{"type":"pair","query":{{"domain":"{}","qtype":{},"client_ip":"{}","client_port":{},"server_ip":"{}","server_port":{},"transaction_id":{},"timestamp_ms":{},"raw_hex":"{}"}},"response":{{"rcode":{},"status":"{}","ancount":{},"client_ip":"{}","client_port":{},"server_ip":"{}","server_port":{},"transaction_id":{},"timestamp_ms":{},"rtt_us":{},"raw_hex":"{}"}},"rtt_us":{}}}"#,
                        escape_json(&pending.domain),
                        pending.qtype,
                        pending.client_ip,
                        pending.client_port,
                        pending.server_ip,
                        pending.server_port,
                        pending.transaction_id,
                        pending.timestamp_ms,
                        pending.raw_hex,
                        rcode_to_u8(&dns_msg.header.flags.rcode),
                        rcode_to_str(&dns_msg.header.flags.rcode),
                        ancount,
                        parsed.client_ip,
                        parsed.client_port,
                        parsed.server_ip,
                        parsed.server_port,
                        tx_id,
                        now_ms,
                        rtt_us,
                        response_raw_hex,
                        rtt_us
                    );
                    sse_broadcaster.broadcast_str(&pair_json);

                    // Update latency histogram
                    {
                        let mut histogram = http_state.histogram.lock().unwrap();
                        histogram.insert(rtt_us as u32);
                    }

                    // Push response to ring buffer
                    counters.total_responses += 1;
                    if dns_msg.header.flags.rcode != Rcode::NoError {
                        counters.timeouts += 1;
                    }
                    match dns_msg.header.flags.rcode {
                        dnssniff_core::dns_proto::header::Rcode::ServFail => counters.servfail += 1,
                        dnssniff_core::dns_proto::header::Rcode::NxDomain => counters.nxdomain += 1,
                        dnssniff_core::dns_proto::header::Rcode::Refused => counters.refused += 1,
                        _ => {}
                    }
                } else {
                    // Unmatched response
                    let pair_json = format!(r#"{{"type":"response","rcode":{},"status":"{}","ancount":{},"client_ip":"{}","client_port":{},"server_ip":"{}","server_port":{},"transaction_id":{},"timestamp_ms":{}}}"#,
                        rcode_to_u8(&dns_msg.header.flags.rcode),
                        rcode_to_str(&dns_msg.header.flags.rcode),
                        ancount,
                        parsed.client_ip,
                        parsed.client_port,
                        parsed.server_ip,
                        parsed.server_port,
                        tx_id,
                        now_ms
                    );
                    sse_broadcaster.broadcast_str(&pair_json);
                    counters.total_responses += 1;
                    if dns_msg.header.flags.rcode != Rcode::NoError {
                        counters.timeouts += 1;
                    }
                    match dns_msg.header.flags.rcode {
                        dnssniff_core::dns_proto::header::Rcode::ServFail => counters.servfail += 1,
                        dnssniff_core::dns_proto::header::Rcode::NxDomain => counters.nxdomain += 1,
                        dnssniff_core::dns_proto::header::Rcode::Refused => counters.refused += 1,
                        _ => {}
                    }
                }
            } else {
                // QUERY — store for later matching
                let domain_clone = domain.to_string();
                let query_raw_hex: String = buf[..n.min(256)]
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect();
                let pending = PendingQuery {
                    timestamp_ms: now_ms,
                    domain: domain_clone.clone(),
                    qtype,
                    client_ip: parsed.client_ip,
                    server_ip: parsed.server_ip,
                    client_port: parsed.client_port,
                    server_port: parsed.server_port,
                    transaction_id: tx_id,
                    raw_hex: query_raw_hex.clone(),
                };
                pending_queries.lock().unwrap().insert(pair_key, pending);

                // Send query-only event
                let pair_json = format!(r#"{{"type":"query","domain":"{}","qtype":{},"client_ip":"{}","client_port":{},"server_ip":"{}","server_port":{},"transaction_id":{},"timestamp_ms":{},"raw_hex":"{}"}}"#,
                    escape_json(&domain_clone),
                    qtype,
                    parsed.client_ip,
                    parsed.client_port,
                    parsed.server_ip,
                    parsed.server_port,
                    tx_id,
                    now_ms,
                    query_raw_hex
                );
                sse_broadcaster.broadcast_str(&pair_json);

                counters.total_queries += 1;
                counters.active_queries += 1;

                // Track question domain
                if args.verbose {
                    println!(
                        "  DNS query: {} type={} class={} from {}:{}",
                        domain,
                        qtype,
                        dns_msg.questions.first().map(|q| q.qclass).unwrap_or(0),
                        parsed.client_ip,
                        parsed.client_port
                    );
                    std::io::stdout().flush().unwrap();
                }
            }

            drop(counters);
        }

        unsafe { raw_close(fd) };
}

/// Minimal unsafe wrappers around libc FFI calls.
/// Each function contains exactly one unsafe FFI call.
unsafe fn raw_if_nametoindex(name: *const i8) -> u32 {
    libc::if_nametoindex(name)
}

unsafe fn raw_geteuid() -> libc::uid_t {
    libc::geteuid()
}

unsafe fn raw_socket(domain: c_int, ty: c_int, protocol: c_int) -> io::Result<c_int> {
    let fd = libc::socket(domain, ty, protocol);
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fd)
}

unsafe fn raw_close(fd: c_int) {
    let _ = libc::close(fd);
}

unsafe fn raw_ioctl(fd: c_int, request: c_ulong, arg: *mut c_void) -> c_int {
    libc::ioctl(fd, request, arg)
}

unsafe fn raw_bind(fd: c_int, addr: *const libc::sockaddr, addrlen: socklen_t) -> c_int {
    libc::bind(fd, addr, addrlen)
}

unsafe fn raw_recvfrom(fd: c_int, buf: *mut c_void, len: usize, flags: c_int, addr: *mut libc::sockaddr, addrlen: *mut socklen_t) -> c_int {
    libc::recvfrom(fd, buf, len, flags, addr, addrlen) as c_int
}
