//! Capture module: raw AF_PACKET socket ingestion with cBPF filtering.
//!
//! Provides:
//! - `RawSocket`: Linux raw socket wrapper with non-blocking I/O
//! - `PacketCapture`: trait for receiving filtered DNS packets
//! - BPF bytecode generation for `(ip and udp port 53) or (ip6 and udp port 53)`

pub mod socket;
pub mod bpf;

use std::os::unix::io::AsRawFd;

/// Data Link Type constants from Linux kernel.
pub mod dlt {
    pub const EN10MB: i32 = 1;   // Ethernet (10Mb)
    pub const LINUX_SLL: i32 = 113; // Linux cooked capture (for "any")
}

/// Trait for packet capture sources.
pub trait PacketCapture: AsRawFd {
    /// Receive the next DNS packet into the provided buffer.
    /// Returns (bytes_read, interface_index) or WouldBlock.
    fn recv_dns_packet(&self, buf: &mut [u8]) -> std::io::Result<(usize, i32)>;
}

pub use bpf::attach_bpf_filter;
pub use self::socket::RawSocket;

/// Open a non-blocking AF_PACKET raw socket bound to the given interface.
/// If `iface` is None, binds to all interfaces (index 0, "-i any").
pub fn open_raw_socket(iface: Option<&str>, socket_type: &str) -> std::io::Result<RawSocket> {
    RawSocket::open(iface, socket_type)
}

impl PacketCapture for RawSocket {
    fn recv_dns_packet(&self, buf: &mut [u8]) -> std::io::Result<(usize, i32)> {
        self.recv_dns_packet(buf)
    }
}
