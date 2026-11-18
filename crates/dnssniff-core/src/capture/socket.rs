//! Linux AF_PACKET raw socket wrapper.
//!
//! Creates a non-blocking raw socket on ETH_P_ALL, binds to a specific
//! interface or all interfaces ("any"), and configures SO_RCVBUF to 512 KB.
//! Promiscuous mode and all-multicast are enabled so the interface captures
//! all traffic regardless of destination MAC or multicast group.

use libc::{c_int, c_ushort, c_void, socklen_t, sockaddr, sockaddr_ll, packet_mreq};
use std::os::unix::io::{AsRawFd, RawFd};
use std::ffi::CString;
use std::io;

/// Wrapper around a Linux raw packet socket file descriptor.
pub struct RawSocket {
    fd: RawFd,
    ifindex: i32,
}

impl RawSocket {
    /// Open and bind an AF_PACKET raw socket.
    ///
    /// If `iface` is `Some(name)`, binds only to that interface.
    /// If `None`, binds to all interfaces.
    pub fn open(iface: Option<&str>, socket_type: &str) -> io::Result<Self> {
        unsafe {
            let sock_type = match socket_type {
                "dgram" => libc::SOCK_DGRAM,
                _ => libc::SOCK_RAW,
            };
            let fd = libc::socket(
                libc::AF_PACKET,
                sock_type | libc::SOCK_CLOEXEC,
                libc::ETH_P_ALL.to_be() as c_int,
            );
            eprintln!("INFO: socket type={} (SOCK_{})", socket_type, if sock_type == libc::SOCK_DGRAM { "DGRAM" } else { "RAW" });
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }

            let ifindex = match iface {
                Some(name) => {
                    let c_name = CString::new(name)
                        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "interface name contains NUL"))?;
                    let idx = libc::if_nametoindex(c_name.as_ptr());
                    if idx == 0 {
                        let _ = libc::close(fd);
                        return Err(io::Error::new(
                            io::ErrorKind::NotFound,
                            format!("interface '{}' not found", name),
                        ));
                    }
                    idx as i32
                }
                None => 0, // capture on all interfaces
            };

            // Always bind using sockaddr_ll (required for AF_PACKET sockets)
            // SO_BINDTODEVICE is NOT supported for packet sockets per socket(7)
            let addr: sockaddr_ll = sockaddr_ll {
                sll_family: libc::AF_PACKET as c_ushort,
                sll_protocol: libc::ETH_P_ALL.to_be() as u16,
                sll_ifindex: ifindex,
                sll_hatype: 0,
                sll_pkttype: 0,
                sll_halen: 0,
                sll_addr: [0; 8],
            };
            let ret = libc::bind(
                fd,
                &addr as *const sockaddr_ll as *const sockaddr,
                std::mem::size_of::<sockaddr_ll>() as socklen_t,
            );
            if ret < 0 {
                let _ = libc::close(fd);
                return Err(io::Error::last_os_error());
            }
            if let Some(name) = iface {
                eprintln!("INFO: bound to interface '{}' (ifindex={})", name, ifindex);
            } else {
                eprintln!("INFO: bound to all interfaces (ifindex=0)");
            }

            // Try SO_BINDTODEVICE as additional option (not a replacement for bind)
            if let Some(name) = iface {
                let c_name = CString::new(name).unwrap();
                let ret = libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_BINDTODEVICE,
                    c_name.as_ptr() as *const c_void,
                    name.len() as socklen_t,
                );
                if ret < 0 {
                    eprintln!("INFO: SO_BINDTODEVICE not supported (ignored): {}", io::Error::last_os_error());
                } else {
                    eprintln!("INFO: SO_BINDTODEVICE also set for '{}'", name);
                }
            }

            // Enable promiscuous mode so we capture all traffic on the interface
            if let Err(e) = Self::set_promiscuous(fd, ifindex) {
                eprintln!("WARNING: failed to set promiscuous mode: {e} (capture may be limited)");
            }

            // Enable all-multicast so we receive multicast packets
            if let Err(e) = Self::set_allmulticast(fd, ifindex) {
                eprintln!("WARNING: failed to set all-multicast: {e} (multicast traffic may be missed)");
            }

            // Expand socket receive buffer to 512 KB
            let rcvbuf: c_int = 512 * 1024;
            let ret = libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                &rcvbuf as *const c_int as *const c_void,
                std::mem::size_of::<c_int>() as socklen_t,
            );
            if ret < 0 {
                eprintln!("WARNING: failed to set SO_RCVBUF: {}", io::Error::last_os_error());
            }

            eprintln!("INFO: raw socket opened (fd={}, ifindex={})", fd, ifindex);

            Ok(RawSocket { fd, ifindex })
        }
    }

    /// Enable promiscuous mode on the interface via PACKET_ADD_MEMBERSHIP.
    fn set_promiscuous(fd: c_int, ifindex: i32) -> io::Result<()> {
        unsafe {
            let mut mr: packet_mreq = std::mem::zeroed();
            mr.mr_ifindex = ifindex;
            mr.mr_type = libc::PACKET_MR_PROMISC as u16;
            mr.mr_alen = 0;
            mr.mr_address = [0; 8];

            let ret = libc::setsockopt(
                fd,
                libc::SOL_PACKET,
                libc::PACKET_ADD_MEMBERSHIP,
                &mr as *const packet_mreq as *const c_void,
                std::mem::size_of::<packet_mreq>() as socklen_t,
            );
            if ret < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }
    }

    /// Enable all-multicast mode via PACKET_ADD_MEMBERSHIP with PACKET_MR_ALLMULTI.
    fn set_allmulticast(fd: c_int, ifindex: i32) -> io::Result<()> {
        unsafe {
            let mut mr: packet_mreq = std::mem::zeroed();
            mr.mr_ifindex = ifindex;
            mr.mr_type = libc::PACKET_MR_ALLMULTI as u16;
            mr.mr_alen = 0;
            mr.mr_address = [0; 8];

            let ret = libc::setsockopt(
                fd,
                libc::SOL_PACKET,
                libc::PACKET_ADD_MEMBERSHIP,
                &mr as *const packet_mreq as *const c_void,
                std::mem::size_of::<packet_mreq>() as socklen_t,
            );
            if ret < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }
    }

    /// Receive a packet into the provided buffer.
    /// Returns (bytes_read, interface_index).
    ///
    /// Note: passes null for src_addr/addrlen in recvfrom to match the
    /// working test sniffer. On WSL2, passing a non-null sockaddr_ll can
    /// cause recvfrom to not return any packets.
    pub fn recv_dns_packet(&self, buf: &mut [u8]) -> io::Result<(usize, i32)> {
        unsafe {
            let n = libc::recvfrom(
                self.fd,
                buf.as_mut_ptr() as *mut c_void,
                buf.len(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            );

            if n < 0 {
                let err = io::Error::last_os_error();
                match err.kind() {
                    io::ErrorKind::Interrupted => return self.recv_dns_packet(buf),
                    _ => return Err(err),
                }
            }

            Ok((n as usize, self.ifindex))
        }
    }

    /// Get the interface index this socket is bound to.
    pub fn ifindex(&self) -> i32 {
        self.ifindex
    }
}

impl AsRawFd for RawSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl Drop for RawSocket {
    fn drop(&mut self) {
        unsafe {
            let _ = libc::close(self.fd);
        }
    }
}
