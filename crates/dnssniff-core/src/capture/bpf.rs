//! Classical BPF (cBPF) bytecode generator for DNS port 53 filtering.
//!
//! Generates kernel-level filter bytecode for `(ip and udp port 53) or (ip6 and udp port 53)`,
//! accounting for Data Link Type (DLT_EN10MB vs DLT_LINUX_SLL).
//!
//! Jump semantics: `pc = pc + 1 + jt` on match, `pc = pc + 1 + jf` on non-match.

use libc::{c_void, socklen_t};
use std::io;

// BPF instruction codes
const BPF_LD: u16 = 0x00;
const BPF_JMP: u16 = 0x05;
const BPF_RET: u16 = 0x06;

// Source field modifiers
const BPF_ABS: u16 = 0x20;

// Instruction base classes
const BPF_H: u16 = 0x08;
const BPF_B: u16 = 0x10;

// Jump operations
const BPF_JEQ: u16 = 0x10;

// Return actions
const BPF_K: u16 = 0x00;

// Max packet size to capture
const CAPTURE_LEN: u32 = 65535;
const DROP: u32 = 0;

/// A single BPF instruction.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SockFilter {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

impl SockFilter {
    pub fn new(code: u16, jt: u8, jf: u8, k: u32) -> Self {
        SockFilter { code, jt, jf, k }
    }
}

fn ld_abs_half(offset: u32) -> SockFilter {
    SockFilter::new(BPF_LD | BPF_H | BPF_ABS, 0, 0, offset)
}

fn ld_abs_byte(offset: u32) -> SockFilter {
    SockFilter::new(BPF_LD | BPF_B | BPF_ABS, 0, 0, offset)
}

fn jmp_jeq(k: u32, jt: u8, jf: u8) -> SockFilter {
    SockFilter::new(BPF_JMP | BPF_JEQ | BPF_K, jt, jf, k)
}

fn ret_imm(k: u32) -> SockFilter {
    SockFilter::new(BPF_RET | BPF_K, 0, 0, k)
}

/// BPF program descriptor for setsockopt(SO_ATTACH_FILTER).
#[repr(C)]
pub struct SockFprog {
    pub len: u16,
    pub filter: *const SockFilter,
}

/// Generate cBPF bytecode for filtering DNS traffic.
pub fn generate_bpf_filter(dlt: i32) -> Vec<SockFilter> {
    match dlt {
        crate::capture::dlt::LINUX_SLL => generate_bpf_filter_sll(),
        _ => build_ethernet_bpf(),
    }
}

/// Build the complete Ethernet BPF program with correct jump offsets.
///
/// Program layout (all jumps forward, verified):
///   [0]  ldh [12]                    # ethertype
///   [1]  jeq 0x0800 -> [4]           # IPv4 handler
///   [2]  jeq 0x86dd -> [13]          # IPv6 handler
///   [3]  ret #0                      # drop (not IP)
///   [4]  ldb [23]                    # IPv4 protocol byte
///   [5]  jeq 17 -> [7]               # UDP handler
///   [6]  ret #0                      # drop (not UDP)
///   [7]  ldh [34]                    # UDP src port
///   [8]  jeq 53 -> [20]              # accept if src port 53
///   [9]  ldh [36]                    # UDP dst port
///   [10] jeq 53 -> [20]              # accept if dst port 53
///   [11] ret #0                      # drop (neither port 53)
///   [12] ldb [20]                    # IPv6 next header
///   [13] jeq 17 -> [15]              # UDP handler
///   [14] ret #0                      # drop (not UDP)
///   [15] ldh [54]                    # UDP6 src port
///   [16] jeq 53 -> [20]              # accept if src port 53
///   [17] ldh [56]                    # UDP6 dst port
///   [18] jeq 53 -> [20]              # accept if dst port 53
///   [19] ret #0                      # drop (neither port 53)
///   [20] ret #65535                  # accept
fn build_ethernet_bpf() -> Vec<SockFilter> {
    let mut insns: Vec<SockFilter> = Vec::new();

    // [0] Load ethertype at offset 12
    insns.push(ld_abs_half(12));
    // [1] If ethertype == 0x0800 (IPv4), jump to [4]; else fall to [2]
    insns.push(jmp_jeq(0x0800, 2, 0));
    // [2] If ethertype == 0x86DD (IPv6), jump to [13]; else fall to [3]
    insns.push(jmp_jeq(0x86dd, 10, 0));
    // [3] Not IPv4 or IPv6: drop
    insns.push(ret_imm(DROP));

    // [4] Load IP protocol byte at offset 23
    insns.push(ld_abs_byte(23));
    // [5] If protocol == 17 (UDP), jump to [7]; else fall to [6]
    insns.push(jmp_jeq(17, 1, 0));
    // [6] Not UDP: drop
    insns.push(ret_imm(DROP));

    // [7] Load UDP source port at offset 34 (14 + 20)
    insns.push(ld_abs_half(34));
    // [8] If src_port == 53, jump to [20] (accept); else fall to [9]
    insns.push(jmp_jeq(53, 11, 0));
    // [9] Load UDP destination port at offset 36
    insns.push(ld_abs_half(36));
    // [10] If dst_port == 53, jump to [20] (accept); else fall to [11]
    insns.push(jmp_jeq(53, 9, 0));
    // [11] Neither port is 53: drop
    insns.push(ret_imm(DROP));

    // [12] Load IPv6 Next Header at offset 20 (14 + 6)
    insns.push(ld_abs_byte(20));
    // [13] If next_header == 17 (UDP), jump to [15]; else fall to [14]
    insns.push(jmp_jeq(17, 1, 0));
    // [14] Not UDP: drop
    insns.push(ret_imm(DROP));

    // [15] Load UDP6 source port at offset 54 (14 + 40)
    insns.push(ld_abs_half(54));
    // [16] If src_port == 53, jump to [20] (accept); else fall to [17]
    insns.push(jmp_jeq(53, 3, 0));
    // [17] Load UDP6 destination port at offset 56
    insns.push(ld_abs_half(56));
    // [18] If dst_port == 53, jump to [20] (accept); else fall to [19]
    insns.push(jmp_jeq(53, 1, 0));
    // [19] Neither port is 53: drop
    insns.push(ret_imm(DROP));

    // [20] Accept (capture full packet)
    insns.push(ret_imm(CAPTURE_LEN));

    insns
}

/// Generate cBPF for Linux Cooked Capture (DLT_LINUX_SLL).
/// Used when binding to "any" interface (sll_ifindex = 0).
///
/// SLL header is 16 bytes. IP payload starts at offset 16.
///   IPv4 protocol byte at offset 25 (16 + 9)
///   IPv6 next header at offset 22 (16 + 6)
///   UDPv4 src/dst ports at offsets 36/38 (16 + 20 / 16 + 22)
///   UDPv6 src/dst ports at offsets 56/58 (16 + 40 / 16 + 42)
fn generate_bpf_filter_sll() -> Vec<SockFilter> {
    let mut insns: Vec<SockFilter> = Vec::new();

    // [0] Load SLL protocol at offset 14
    insns.push(ld_abs_half(14));
    // [1] If protocol == 0x0800 (IPv4), jump to [4]; else fall to [2]
    insns.push(jmp_jeq(0x0800, 2, 0));
    // [2] If protocol == 0x86DD (IPv6), jump to [13]; else fall to [3]
    insns.push(jmp_jeq(0x86dd, 10, 0));
    // [3] Not IP: drop
    insns.push(ret_imm(DROP));

    // [4] Load IP protocol byte at offset 25
    insns.push(ld_abs_byte(25));
    // [5] If protocol == 17 (UDP), jump to [7]; else fall to [6]
    insns.push(jmp_jeq(17, 1, 0));
    // [6] Not UDP: drop
    insns.push(ret_imm(DROP));

    // [7] Load UDP source port at offset 36
    insns.push(ld_abs_half(36));
    // [8] If src_port == 53, jump to [20] (accept); else fall to [9]
    insns.push(jmp_jeq(53, 11, 0));
    // [9] Load UDP destination port at offset 38
    insns.push(ld_abs_half(38));
    // [10] If dst_port == 53, jump to [20] (accept); else fall to [11]
    insns.push(jmp_jeq(53, 9, 0));
    // [11] Neither port is 53: drop
    insns.push(ret_imm(DROP));

    // [12] Load IPv6 Next Header at offset 22
    insns.push(ld_abs_byte(22));
    // [13] If next_header == 17 (UDP), jump to [15]; else fall to [14]
    insns.push(jmp_jeq(17, 1, 0));
    // [14] Not UDP: drop
    insns.push(ret_imm(DROP));

    // [15] Load UDP6 source port at offset 56
    insns.push(ld_abs_half(56));
    // [16] If src_port == 53, jump to [20] (accept); else fall to [17]
    insns.push(jmp_jeq(53, 3, 0));
    // [17] Load UDP6 destination port at offset 58
    insns.push(ld_abs_half(58));
    // [18] If dst_port == 53, jump to [20] (accept); else fall to [19]
    insns.push(jmp_jeq(53, 1, 0));
    // [19] Neither port is 53: drop
    insns.push(ret_imm(DROP));

    // [20] Accept (capture full packet)
    insns.push(ret_imm(CAPTURE_LEN));

    insns
}

/// Attach a cBPF filter to a raw socket.
pub fn attach_bpf_filter(fd: libc::c_int, dlt: i32) -> io::Result<Vec<SockFilter>> {
    let filter = generate_bpf_filter(dlt);
    let prog = SockFprog {
        len: filter.len() as u16,
        filter: filter.as_ptr(),
    };

    unsafe {
        let ret = libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ATTACH_FILTER,
            &prog as *const SockFprog as *const c_void,
            std::mem::size_of::<SockFprog>() as socklen_t,
        );
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
    }

    Ok(filter)
}
