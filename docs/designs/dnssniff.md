# dnssniff: Lightweight Embedded DNS Sniffer & Web Telemetry for OpenWrt

*   **Author:** Naushit Sakarvadia
*   **Status:** Draft
*   **Date:** 2026-11-16

--------------------------------------------------------------------------------

## Overview

`dnssniff` is a lightweight, zero-persistence DNS packet sniffer and diagnostic telemetry tool written in Rust for resource-constrained embedded Linux environments, specifically OpenWrt routers. Operating passively on network interfaces, it decodes UDP port 53 DNS transactions in real time to diagnose resolution failures, response latency, and network drop events. 

It provides an embedded single-page web dashboard (under 20 KB) served directly by an internal non-blocking HTTP server alongside raw JSON metrics endpoints. Designed for embedded systems with tight flash storage and memory constraints, `dnssniff` requires no external C libraries (such as `libpcap`), eliminates persistent disk writes to prevent flash wear, and enforces a strict 32 MB RAM operational ceiling with a baseline memory footprint of 4.8 MB to 6.8 MB RSS.

## The Problem

Diagnosing DNS issues on consumer and edge routers (such as OpenWrt devices) is painful and inefficient:
1. **Tooling Gaps on Constrained Targets**: Standard packet analysis tools like `wireshark` cannot run on embedded routers. Minimal CLI alternatives like `tcpdump` generate unparsed packet hex dumps or require shipping `.pcap` files off-router, while tools like `dnstop` only provide aggregate counters without transaction-level latency or deep packet inspection.
2. **Dynamic Linking & Cross-Compilation Fragility**: Existing sniffing tools in Rust or Python depend on `libpcap` or Python interpreters, requiring external packages (`opkg install libpcap`) that often fail or exceed storage capacity on devices with 16 MB or 32 MB flash storage.
3. **Flash Wear & Ephemeral Diagnostic Needs**: Standard daemons log extensively to disk, accelerating NAND/NOR flash degradation. Router diagnostics require an ephemeral tool that maintains bounded in-memory state and leaves zero disk footprint upon termination.
4. **Offline Diagnostic Accessibility**: When upstream DNS or WAN connectivity fails, network administrators need an immediate, local diagnostic interface. Remote web applications fail to load when the internet is down, while complex terminal interfaces cause screen tearing and high CPU utilization over slow serial or SSH connections.

`dnssniff` resolves these issues by pairing Linux in-kernel socket filtering with a self-contained, offline-first web dashboard that runs entirely in volatile RAM.

## Goals

*   **Zero External C Dependencies & Universal Interface Binding**: Sniff raw UDP port 53 packets using native Linux `AF_PACKET` raw sockets with attached in-kernel classic BPF (cBPF) filters, enabling static cross-compilation with `musl` without `libpcap`. Support capturing on specific network interfaces (e.g., `-i br-lan`, `-i eth0`) or capturing across all interfaces via `-i any`.
*   **Strict Memory Bounding (< 32 MB RAM Ceiling)**: Maintain an active operational memory footprint under 6.8 MB RSS during normal traffic, and strictly enforce an absolute ceiling of 32 MB under high-volume query bursts via pre-allocated bounded ring buffers and bounded queue allocations.
*   **Zero Disk Persistence**: Store all transient packet summaries, in-flight transaction tables, and error buffers purely in RAM; write zero bytes to disk or flash storage.
*   **In-Memory Transaction Correlation & Anomaly Detection**: Match DNS queries and responses using 5-tuple IP/port addresses and 16-bit Transaction IDs to measure round-trip time (RTT in microseconds) and classify unacknowledged queries after a configurable timeout (default: 3.0 seconds).
*   **Portable & Decoupled Web/Telemetry Server**: Structure the HTTP and Server-Sent Events (SSE) server as a reusable, decoupled module/crate with clean data-feed traits, enabling reuse in other DNS-related projects.
*   **Two-Tier Frontend Architecture (Local Embedded + Local/Offline WASM Analytics)**:
    *   **Tier 1 (Embedded Lightweight Dashboard)**: Self-contained single-page dashboard (< 20 KB) served directly by the router at `GET /` for instant, offline, zero-dependency LAN diagnostics.
    *   **Tier 2 (Offline-Capable WASM Analytics Suite)**: An independent, browser-based WebAssembly application delivered either as a local file, bundled router web package, or offline snapshot analyzer. It connects locally to the router's JSON/SSE endpoints or imports exported snapshots (`GET /export.json`) to perform compute-heavy analytics (in-browser ad-server blocklist hash table lookups, logarithmic latency histograms, query grouping by major autonomous networks/subnets) entirely within the user's browser, offloading all analytical overhead from the router SoC without incurring browser Mixed Content blocks.
*   **Controlled Local Access & Security**: Implement safe LAN CORS policies (`Access-Control-Allow-Origin` restricted to local LAN/loopback origins) with optional token authentication, preventing malicious external web pages from silently siphoning private LAN DNS query streams.
*   **Zero-Dependency Raw JSON Telemetry**: Expose an HTTP endpoint (`GET /stats`) delivering machine-readable JSON metrics (query rates, error counts by RCODE, and logarithmic latency percentiles) for integration with OpenWrt shell scripts, `ubus` proxies, or external monitoring agents.
*   **Sub-Megabyte Binary Footprint**: Target a compiled and stripped binary size between 550 KB and 650 KB on MIPS and ARM musl targets.

## Non-Goals

*   **Public HTTPS CDN Hosting for Diagnostics**: Hosting diagnostic web interfaces on public HTTPS domains (e.g., GitHub Pages) that query unencrypted local router HTTP endpoints is explicitly excluded to prevent browser Mixed Content blocking and maintain 100% offline diagnostic availability during WAN outages.
*   **TCP DNS Stream Reassembly (v1)**: Tracking TCP DNS sessions (port 53 TCP) is out of scope for initial release; capture is restricted strictly to UDP port 53 datagrams.
*   **Encrypted DNS Inspection**: Passive interception or decryption of DNS-over-HTTPS (DoH, port 443) or DNS-over-TLS (DoT, port 853) is strictly out of scope.
*   **On-Router Heavy Analytics & Threat Feeds**: Running ad-server blocklist hash tables, threat intelligence feeds, or heavy statistical clustering on the router itself is out of scope. These analytical tasks are strictly offloaded to the external WASM client's browser memory.
*   **Persistent Historical Storage**: Long-term database storage (SQLite, RocksDB) or historical telemetry persistence is excluded; all state is cleared on process exit.
*   **Active Traffic Manipulation**: `dnssniff` is strictly a passive sniffer. Packet modification, DNS spoofing, NXDOMAIN hijacking, or firewall redirection will not be implemented.
*   **Baseline Terminal User Interface (TUI)**: Terminal interfaces using `ratatui`/`crossterm` are excluded from the default binary to minimize size and prevent serial console latency (retained strictly as a feature-gated stretch goal).

## Open Questions

None. All architectural questions are resolved:
*   Interface binding supports both specific interfaces (`-i <interface>`) and all interfaces simultaneously (`-i any`).
*   Real-time browser telemetry delivery is implemented via Server-Sent Events (`GET /events`).
*   Frontend delivery enforces local/offline same-origin or snapshot analysis to eliminate browser Mixed Content security failures.

## Critical User Journeys (CUJs)

### CUJ 1: Triage Client DNS Timeouts & Local Forwarder Failures from OpenWrt Router

*   **Given**: An OpenWrt router where LAN clients experience intermittent resolution failures; the local DNS forwarder (`dnsmasq`) is listening on `192.168.1.1:53`; the operator is connected via local LAN.
*   **When**: The operator executes `dnssniff -i br-lan --http-port 9153` via SSH and navigates to `http://192.168.1.1:9153/` in a web browser.
*   **Then**: The browser displays the embedded split-view dashboard. The operator selects the "Errors" view, immediately seeing client-to-router transactions marked as `TIMEOUT_NO_RESPONSE` with their query domain, client source IP, and elapsed wait time. Clicking a failed transaction reveals the decoded DNS question record.

### CUJ 2: Continuous Telemetry Export for Router Health Monitoring

*   **Given**: `dnssniff` is configured as a background service managed by OpenWrt's process supervisor (`procd`) listening on `0.0.0.0:9153`.
*   **When**: A local shell script or OpenWrt microbus (`ubus`) RPC helper issues `curl -s http://127.0.0.1:9153/stats`.
*   **Then**: `dnssniff` responds within 2 milliseconds with a raw JSON payload containing uptime, total queries, latency percentiles (p50, p90, p99 in microseconds), and categorized error counters (NXDOMAIN, SERVFAIL, timeouts) without allocating dynamic heap objects.

### CUJ 3: Deep Offline/Online Analytics via Local WASM Suite or Snapshot Export

*   **Given**: An administrator wants to analyze network traffic patterns, latency trends, and ad/tracker queries on their LAN; `dnssniff` is running on the router at `192.168.1.1:9153`.
*   **When**: The administrator opens the locally served or offline WASM analytics suite in a desktop browser (loaded from `http://192.168.1.1:9153/wasm/` or via local file snapshot import from `http://192.168.1.1:9153/export.json`).
*   **Then**: The WASM client ingests transactions, matches full domain names against an in-browser ad-server hash table, plots real-time logarithmic latency histograms, and categorizes query volumes by autonomous network without increasing router memory or CPU utilization, and without triggering browser Mixed Content blocking.

--------------------------------------------------------------------------------

## Technical Plan (Architecture)

### 1. System Architecture Overview & Component Boundaries

The `dnssniff` architecture is partitioned into four decoupled components across two distinct deployment tiers:

```
[ TIER 1: Router Daemon (dnssniff) ]
  +----------------------------------------------------------------------------+
  | Linux Kernel Network Subsystem                                            |
  |   +--------------------------------------------------------------------+   |
  |   | Dynamic cBPF Filter: `(ip and udp port 53) or (ip6 and udp port 53)`|   |
  |   +--------------------------------------------------------------------+   |
  |                                     |                                      |
  |                       recvfrom() into 4KB Stack Buffer                     |
  |                                     v                                      |
  |   +--------------------------------------------------------------------+   |
  |   | dnssniff-core::net_proto: IPv4 / IPv6 & UDP Header Parser          |   |
  |   | - Extract 5-tuple: (Client IP/Port, Server IP/Port, Proto)         |   |
  |   | - Calculate DNS payload offset: &buf[ip_len + 8..]                 |   |
  |   +--------------------------------------------------------------------+   |
  |                                     v                                      |
  |   +--------------------------------------------------------------------+   |
  |   | dnssniff-core::dns_proto: Safe Zero-Alloc RFC 1035 Parser          |   |
  |   +--------------------------------------------------------------------+   |
  |                      |                              |                      |
  |             If Query (QR=0)                 If Response (QR=1)             |
  |                      v                              v                      |
  |   +-------------------------------+   +--------------------------------+   |
  |   | In-Flight Tracker Table       |   | Transaction Matcher            |   |
  |   | (8,192 Bounded Slots)         |   | - Correlate 5-Tuple + ID       |   |
  |   | - Atomic Generation Stamp     |   | - Calculate Latency (rtt_us)   |   |
  |   | - Push FIFO (Instant, Slot,   |   | - Mark Slot Complete in O(1)   |   |
  |   |   Generation) Queue           |   +--------------------------------+   |
  |   +-------------------------------+                 |                      |
  |                      |                              |                      |
  |             On 3s Timeout Expire                    v                      |
  |                      |               +---------------------------------+   |
  |                      +-------------->| Ring Buffers (Zero Persistence) |   |
  |                                      | - Live Ring (1,000 Slots)       |   |
  |                                      | - Error Ring (1,000 Slots)      |   |
  |                                      +---------------------------------+   |
  |                                                     |                      |
  |                                      Broadcast completed transactions      |
  |                                                     v                      |
  |   +--------------------------------------------------------------------+   |
  |   | dnssniff-web: Portable Non-Blocking HTTP & SSE Daemon              |   |
  |   | - GET /         -> Embedded HTML/JS/CSS Single-Page App (<20 KB)   |   |
  |   | - GET /stats    -> Logarithmic latency & machine-readable JSON     |   |
  |   | - GET /events   -> Server-Sent Events stream (lossy slow-consumer) |   |
  |   | - GET /export   -> JSON snapshot of recent transactions            |   |
  |   | - GET /health   -> Liveness check                                  |   |
  |   | - Safe LAN CORS headers (no unauthenticated wildcard exfiltration) |   |
  |   +--------------------------------------------------------------------+   |
  +----------------------------------------------------------------------------+
                                 |                          |
                     Direct Local HTTP                 Local HTTP /
                     (Same-Origin)                     Snapshot Import
                                 |                          |
                                 v                          v
             +-------------------------+       +-------------------------------+
             | Tier 1 Local Web UI     |       | TIER 2: Offline WASM Suite    |
             | Embedded HTML/JS (<20KB)|       | (Local/Offline Browser Engine)|
             | - Split-window view     |       | - Ad-Server Hash Table Lookup |
             | - Live vs Error toggles |       | - High-res Latency Histograms |
             | - Decoded packet viewer |       | - Autonomous Network Grouping |
             | - 100% Offline-capable  |       | - Clean Same-Origin / No Mixed|
             +-------------------------+       +-------------------------------+
```

---

### 2. Low-Level Component Specifications

#### A. Kernel Packet Filtering & Socket Ingestion (`dnssniff-core::capture`)
*   **Socket Abstraction**: Opens a non-blocking Linux raw socket via `socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ALL))` to bypass layer-2 Ethernet headers and receive raw IP/IPv6 packets.
*   **POSIX Interface Binding**:
    *   Specific Interface (`-i br-lan` or `-i eth0`): Resolves the interface index via `if_nametoindex()` and binds using standard POSIX `bind()` with `struct sockaddr_ll { sll_family: AF_PACKET, sll_protocol: htons(ETH_P_ALL), sll_ifindex: ifindex }`.
    *   Universal Binding (`-i any`): Binds with `sll_ifindex: 0`, capturing across all active system interfaces simultaneously.
*   **Dynamic cBPF Filter Assembly**: Generates classic BPF assembly bytecode based on the Data Link Type (DLT) of the bound interface:
    *   Standard Ethernet (`DLT_EN10MB`): Accounts for standard 14-byte link-layer offsets and skips 4-byte 802.1Q VLAN headers (`0x8100`).
    *   Linux Cooked Capture (`DLT_LINUX_SLL` on `-i any`): Accounts for 16-byte cooked headers.
    *   Filter logic enforces: `(ip and udp port 53) or (ip6 and udp port 53)` with explicit grouping parentheses, ensuring kernel-space dropping of all non-DNS frames before userspace copying.

#### B. Network & Transport Layer Decoding (`dnssniff-core::net_proto`)
*   **IP/UDP Header Unpacking**:
    *   Inspects the IP version from the first nibble of the received slice (`buf[0] >> 4`).
    *   IPv4: Reads IHL (Internet Header Length), validates total length, extracts source IP (`buf[12..16]`) and destination IP (`buf[16..20]`), and verifies protocol == 17 (UDP). Header length is `IHL * 4` (20 to 60 bytes).
    *   IPv6: Validates 40-byte fixed header, extracts source IP (`buf[8..24]`) and destination IP (`buf[24..40]`), and verifies Next Header == 17 (UDP).
    *   UDP: Extracts source port and destination port from the 8-byte UDP header. Validates UDP length.
*   **DNS Payload Slicing**: Advances the borrowed slice by `ip_header_len + 8`, passing only the exact DNS payload bytes to `dns_proto`.

#### C. Safe Zero-Alloc Wire Parser (`dnssniff-core::dns_proto`)
*   **Zero Heap Allocation**: Parses DNS messages directly out of borrowed stack slices (`&[u8]`).
*   **Header Decoding**: Extracts the 16-bit Transaction ID, Flags (QR, Opcode, AA, TC, RD, RA, RCODE), and record counts (QDCOUNT, ANCOUNT) using big-endian bitfield decoding.
*   **RFC 1035 Compression Pointer Safety**: Implements domain name unrolling on borrowed slices with:
    1.  Pointer Detection: Validates pointer prefix `(byte[0] & 0xC0) == 0xC0` with 14-bit offset `(((byte[0] & 0x3F) as u16) << 8) | (byte[1] as u16)`.
    2.  Boundary Validation: The target offset must resolve within the current datagram slice.
    3.  Recursion Limit: Enforces a strict recursion depth limit of **16 pointer hops** to block denial-of-service compression loops while safely parsing deeply nested valid domain delegations.

#### D. In-Flight Transaction Tracker (`dnssniff-core::tracker`)
*   **Correlation Key**:
    *   Combines 5-tuple (`client_ip`, `client_port`, `server_ip`, `server_port`, `transaction_id`) and the ingress interface index (`ifindex`) to prevent NAT asymmetry collisions when sniffing `-i any`.
*   **Bounded Hash Table & Generation Counter**:
    *   Fixed-capacity array-backed slot table containing 8,192 slots.
    *   Each slot holds a 64-bit monotonic generation sequence number.
*   **$O(1)$ Lazy FIFO Timeout Eviction**:
    *   When a query is received, an entry is pushed to `VecDeque<(Instant, u32 /* slot_idx */, u64 /* generation */)>`.
    *   When a response arrives, the query slot is cleared and marked complete in $O(1)$ time without scanning or shifting the queue.
    *   On the periodic 100ms timer tick, the queue head is inspected. If the queue entry's generation matches the slot's current generation and 3.0 seconds have elapsed, it is evicted as `TIMEOUT_NO_RESPONSE`. If the slot generation has incremented (recycled or completed), the queue entry is discarded in $O(1)$ with zero ABA hazard.

#### E. Bounded Circular Ring Buffers (`dnssniff-core::ring`)
*   **`TransactionSummary` Record**:
    *   Timestamp (`u64`, ms), round-trip latency (`rtt_us: u32`, integer microseconds), client IP, server IP, client port, server port, transaction ID, QTYPE, RCODE, status flags.
    *   Domain Storage: Fixed 64-byte inline dot-delimited ASCII buffer (`domain_name: [u8; 64]`), covering 95%+ of queries without allocation.
    *   Extended Arena: A circular 64 KB domain string arena holds full names up to 253 bytes for Server-Sent Events broadcast.
*   **Dual Buffers**:
    *   `live_ring`: Circular buffer holding 1,000 transactions (~128 KB).
    *   `error_ring`: Circular buffer holding 1,000 anomalous/error transactions (~128 KB).

---

### 3. Decoupled Web Server & Telemetry Engine (`dnssniff-web`)

*   **Non-Blocking HTTP Reactor**: Built on `std::net::TcpListener` integrated into the `mio` / `epoll` reactor using `httparse` for zero-alloc HTTP request parsing.
*   **API & Endpoint Specifications**:
    1.  `GET /`: Serves the embedded HTML/JS/CSS dashboard compiled into the binary via `include_str!("assets/index.html")`.
    2.  `GET /stats`: Returns machine-readable raw JSON metrics computed via a fixed 64-bucket logarithmic histogram (HDR histogram) covering 100 µs to 10 s:
        ```json
        {
          "uptime_secs": 1420,
          "active_queries": 12,
          "total_queries": 45120,
          "total_responses": 44890,
          "errors": {
            "timeouts": 210,
            "servfail": 14,
            "nxdomain": 840,
            "refused": 6,
            "malformed": 0
          },
          "latency_us": {
            "p50": 11200,
            "p90": 28400,
            "p99": 92100,
            "avg": 14500
          }
        }
        ```
    3.  `GET /events`: Persistent Server-Sent Events stream:
        ```text
        HTTP/1.1 200 OK
        Content-Type: text/event-stream
        Cache-Control: no-cache

        data: {"id":1420,"rtt_us":12400,"domain":"example.com","qtype":"A","rcode":"NOERROR","status":"OK"}
        ```
    4.  `GET /export.json`: Full JSON dump of current live and error ring buffers for offline analysis.
    5.  `GET /health`: Returns `HTTP 200 OK` with `{"status":"ok"}`.
*   **SSE Slow-Consumer Backpressure Policy**:
    *   Each connected SSE client has a bounded circular send queue (16 events).
    *   If a client socket returns `WouldBlock` and its queue is saturated, incoming events for that client are dropped (incrementing `sse_dropped_events`).
    *   If a client socket fails to drain within 1.0 second, it is disconnected to eliminate capture starvation.
*   **LAN-Restricted CORS & Security**:
    *   CORS headers restrict origins to local LAN subnets and loopback (`localhost`, `127.0.0.1`, `192.168.*`, `10.*`). Wildcard `Access-Control-Allow-Origin: *` on public networks is prohibited.

---

### 4. Offline-First WebAssembly Analytics Engine (`dnssniff-wasm`)

An independent, client-side Rust WebAssembly crate (`dnssniff-wasm`) compiled to `wasm32-unknown-unknown`:
*   **Delivery**: Served locally from the router's web server (`http://192.168.1.1:9153/wasm/`) or run as a local desktop HTML/WASM bundle, completely eliminating browser Mixed Content blocking.
*   **Ad-Server & Tracker Classification**: Loads full domain names into a browser `HashSet<String>` containing popular ad-server hosts (e.g., StevenBlack lists) loaded client-side. Matches incoming queries in real time.
*   **Deep Latency & Autonomous Network Analytics**: Computes full sliding-window latency distributions and maps queried IP ranges to Autonomous System (AS) groupings using HTML5 Canvas.
*   **Zero Router Impact**: Router CPU and RAM usage remains unaffected while the user runs deep analytics.

---

### 5. Memory Envelope & Performance Budgets

| Subsystem / Allocation Target | Allocation Pattern | Max Footprint |
| :--- | :--- | :--- |
| **Ingress Stack Frame** | Fixed 4,096-byte array on stack | 4 KB |
| **In-Flight Tracker Hash Table** | Fixed array (8,192 entries @ 48 bytes) | 393 KB |
| **FIFO Timeout Queue** | `VecDeque<(Instant, u32, u64)>` (8,192 @ 32 bytes) | 256 KB |
| **Live Ring Buffer** | Circular buffer (1,000 entries @ 128 bytes) | 128 KB |
| **Error Ring Buffer** | Circular buffer (1,000 entries @ 128 bytes) | 128 KB |
| **Domain String Arena** | Circular buffer for full domain names | 64 KB |
| **Logarithmic Latency Histogram** | 64 integer buckets @ 8 bytes | 0.5 KB |
| **Embedded HTML/JS Asset** | Read-only `.rodata` static string | ~18 KB |
| **HTTP Client Buffers** | 8 concurrent client buffers @ 4 KB | 32 KB |
| **Runtime Heap & Thread Stack** | Single thread stack (64KB) + musl heap metadata | ~4,200 KB |
| **Total Typical Operational RSS** | Baseline to High Load | **~5.2 MB – 6.8 MB** |
| **Absolute Enforced Ceiling** | Static Pre-allocation & Drop Counters | **< 32.0 MB** |

--------------------------------------------------------------------------------

## Risks & Mitigations

### 1. Kernel Socket Buffer Overflows (`ENOBUFS`) Under Severe Query Floods
*   **Risk**: During a heavy DNS DDoS attack on the LAN (exceeding 20,000 QPS), userspace packet reading may lag behind the packet rate, causing the kernel socket receive buffer to overflow and drop packets silently.
*   **Mitigation**: The socket receive buffer `SO_RCVBUF` is explicitly expanded to 512 KB at startup. Non-blocking `recvfrom()` drains packets in a tight loop per reactor tick. In-kernel cBPF discards non-DNS traffic before buffer entry.

### 2. Network Interface Hotplug and Carrier Flapping
*   **Risk**: On OpenWrt routers, virtual interfaces (`br-lan`) or PPPoE WAN links (`pppoe-wan`) may be torn down or restarted dynamically, invalidating the socket file descriptor.
*   **Mitigation**: `dnssniff` handles `ENETDOWN` and `ENODEV` error codes gracefully by scheduling exponential backoff reconnect attempts without crashing the process.

### 3. IP Packet Fragmentation on Oversized DNS Responses
*   **Risk**: DNS responses with large DNSSEC payloads exceeding standard MTU (1500 bytes) are fragmented across multiple IP packets. Because UDP ports only appear in the first fragment, trailing fragments cannot be correlated.
*   **Mitigation**: `net_proto` identifies IP fragment offset fields. If a packet is a trailing fragment (fragment offset > 0), it is ignored. The first fragment containing the DNS header and Transaction ID is processed normally. Truncated responses (with the `TC` bit set) are explicitly categorized as truncated in the error ring buffer.

### 4. Memory Exhaustion Defense & Upper Ceiling Invariant
*   **Risk**: Traffic surges or malicious query generation might trigger unbounded allocations, risking Linux OOM-killer termination on low-memory routers.
*   **Mitigation**: All internal tables, ring buffers, histograms, and queue slots are strictly pre-allocated at startup. If table capacity (8,192 entries) is exhausted, the oldest pending query is evicted with an increment to `table_overflow_evictions`. Zero heap allocations occur on the packet processing path.

--------------------------------------------------------------------------------

## Alternatives Considered

### Alternative A: `libpcap` C Library Binding
*   **Pros**: Access to high-level capture APIs, established standard tooling ecosystem, and cross-platform capture portability across BSD, macOS, and Linux.
*   **Cons**: Introduces dynamic shared library dependencies (`libpcap.so`), triggers cross-compilation toolchain breakages on embedded targets (e.g., MIPS musl), and requires users to manually install external packages (`opkg install libpcap`) on storage-constrained routers.
*   **Technical Reason for Rejection**: Unacceptable runtime dependency and cross-compilation complexity on bare OpenWrt targets; replaced by native Linux `AF_PACKET` raw sockets with cBPF filtering.

### Alternative B: Baseline Terminal User Interface (TUI)
*   **Pros**: Operates directly inside an SSH terminal session without needing a browser.
*   **Cons**: Terminal rendering crates (`ratatui`, `crossterm`) add ~1.2 MB to the stripped binary. Full-screen terminal redraws cause severe screen tearing and high router CPU usage over low-baud serial lines (115200 baud) or lossy SSH connections.
*   **Technical Reason for Rejection**: Exceeds flash storage budgets on constrained routers and causes terminal latency; deferred to an optional feature-gated stretch goal (`--features tui`) in favor of a sub-megabyte embedded web dashboard (< 20 KB).

### Alternative C: Bundling WASM Frontend Inside the Router Binary
*   **Pros**: Distributes the full-featured rich WebAssembly dashboard directly from the router without external dependencies.
*   **Cons**: Compiling Rust to WebAssembly produces a `.wasm` binary between 500 KB and 2 MB. Storing this asset inside the router binary or on flash memory negates the binary size savings gained from removing the TUI.
*   **Technical Reason for Rejection**: Bloats router binary size and flash storage; resolved via a two-tier model with an ultra-lightweight (< 20 KB) embedded HTML/JS dashboard on the router and an offline-capable WASM analytics suite.

### Alternative D: Remotely Hosted Frontend on Public HTTPS CDN
*   **Pros**: Zero router flash storage used for web assets; UI updates are deployed instantly to CDN.
*   **Cons**: Completely fails when the router's upstream WAN or DNS resolution is down, creating an unacceptable circular dependency for an offline diagnostic tool. Furthermore, modern web browsers enforce Private Network Access (PNA) and Mixed Content blocks preventing public HTTPS pages from calling local HTTP router IPs (`http://192.168.1.1:9153`).
*   **Technical Reason for Rejection**: Prevents offline LAN diagnostics during network outages and violates browser Private Network Access security restrictions when connecting to local router IPs.

### Alternative E: Userspace Packet Filtering (Parsing Raw Ethernet Frames)
*   **Pros**: Eliminates the need to assemble and attach in-kernel classical BPF bytecode instructions.
*   **Cons**: The Linux kernel copies every single packet traversing the interface into userspace. On a gigabit or 100 Mbps LAN, non-DNS traffic overwhelms weak single-core MIPS/ARM router CPUs within seconds.
*   **Technical Reason for Rejection**: Overwhelms router CPU with non-DNS traffic; replaced by in-kernel cBPF filters attached via `SO_ATTACH_FILTER` so the kernel drops non-DNS packets before userspace memory copies.

### Alternative F: Full Packet Buffer Retention in Memory
*   **Pros**: Enables complete packet hex dumps and retrospective `.pcap` downloads for every transaction.
*   **Cons**: Retaining full 512-byte to 4096-byte packet buffers for thousands of transactions causes rapid heap exhaustion and memory fragmentation under `musl`.
*   **Technical Reason for Rejection**: High risk of RAM exhaustion on routers; replaced by ephemeral 4KB stack decoding into compact `TransactionSummary` records stored in bounded circular buffers.

--------------------------------------------------------------------------------

## Non-Functional Requirements

### Security & Isolation
*   **Passive Sniffing Only**: Socket opened strictly in read-only mode (`SOCK_DGRAM`); no packet transmission or raw frame injection capabilities enabled.
*   **Privilege Management**: The binary requires `CAP_NET_RAW` and `CAP_NET_ADMIN` to bind `AF_PACKET` and attach BPF filters. The daemon drops supplementary privileges after socket initialization if running as root.
*   **Loop Denial-of-Service Defense**: RFC 1035 wire parser enforces a strict boundary check and a hard limit of 16 compression pointer hops to prevent malicious packet loops from triggering infinite recursion or CPU hangs.
*   **Local Binding Default**: HTTP daemon binds to `0.0.0.0:9153` with LAN-restricted CORS to prevent unauthorized external cross-origin exfiltration.

### Performance & Flash Wear Prevention
*   **Zero Flash Storage Writes**: All buffers, active query tables, and HTTP metrics exist purely in volatile RAM. No logs are written to `/tmp` (tmpfs) or persistent overlayfs.
*   **CPU Utilization Bound**: In-kernel cBPF drops non-DNS packets in kernel space; the userspace event loop operates at line speed for packet parsing and throttles HTTP/SSE broadcasts to prevent CPU saturation.
*   **Binary Size**: Stripped static binary target is strictly between 550 KB and 650 KB on MIPS and ARM targets.

--------------------------------------------------------------------------------

### Additional Resources
*   [RFC 1035: Domain Names - Implementation and Specification](https://www.ietf.org/rfc/rfc1035.txt)
*   [Linux Kernel Documentation: BPF and Socket Filters](https://docs.kernel.org/bpf/index.html)
*   [W3C Private Network Access Specification](https://wicg.github.io/private-network-access/)
*   [OpenWrt Process Management (procd)](https://openwrt.org/docs/techref/procd)
*   [OpenWrt Unified Configuration Interface (UCI)](https://openwrt.org/docs/guide-user/base-system/uci)

### Future Improvements
*   **Feature-Gated TUI (`--features tui`)**: Optional terminal interface enabled via Cargo feature flags for high-spec routers or x86_64 diagnostics.
*   **TCP DNS Stream Reassembly (v2)**: Tracking 2-byte framed TCP DNS queries on port 53.
*   **eBPF / XDP Support**: On modern Linux router kernels supporting eBPF/XDP, replace cBPF with an XDP capture program for zero-copy ring buffer ingestion.

--------------------------------------------------------------------------------

## Detailed Implementation Plan

### Target Files to Create/Modify

#### 1. `Cargo.toml` (Create)
*   **Type / Scope**: Workspace Root Configuration
*   **Proposed Changes**: Configure Cargo workspace members (`crates/dnssniff-core`, `crates/dnssniff-web`, `crates/dnssniff-cli`, `crates/dnssniff-wasm`). Define aggressive musl release profile optimizations (`panic = "abort"`, `opt-level = "z"`, `lto = true`, `codegen-units = 1`, `strip = true`) to enforce a < 650 KB binary target.

#### 2. `crates/dnssniff-core/Cargo.toml` (Create)
*   **Type / Scope**: Core Library Manifest
*   **Proposed Changes**: Define core dependencies (`libc = "0.2"`, `mio = { version = "0.8", features = ["net", "os-poll"] }`). Zero web or GUI dependencies.

#### 3. `crates/dnssniff-core/src/lib.rs` (Create)
*   **Type / Scope**: Core Library Root
*   **Proposed Changes**: Export public modules `capture`, `net_proto`, `dns_proto`, `tracker`, and `ring`. Define shared telemetry types including `TransactionSummary` and `TransactionKey`.

#### 4. `crates/dnssniff-core/src/capture/mod.rs` (Create)
*   **Type / Scope**: Capture Module Root
*   **Proposed Changes**: Define the `PacketCapture` trait and public constructors.

#### 5. `crates/dnssniff-core/src/capture/socket.rs` (Create)
*   **Type / Scope**: Linux Raw Socket Wrapper
*   **Proposed Changes**: Implement `RawSocket::open(iface: Option<&str>)` creating an `AF_PACKET` socket with `SOCK_DGRAM` and `ETH_P_ALL`. Bind using standard POSIX `bind()` with `sockaddr_ll` (resolving interface index via `if_nametoindex()` or `0` for `-i any`). Set non-blocking mode via `fcntl(O_NONBLOCK)` and configure `SO_RCVBUF` to 512 KB.

#### 6. `crates/dnssniff-core/src/capture/bpf.rs` (Create)
*   **Type / Scope**: Classical BPF Bytecode Generator
*   **Proposed Changes**: Generate Linux cBPF assembly block filter dynamically accounting for Data Link Type (`DLT_EN10MB` 14-byte offset vs `DLT_LINUX_SLL` 16-byte offset for `-i any`), filtering for `(ip and udp port 53) or (ip6 and udp port 53)`. Attach using `setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, ...)`.

#### 7. `crates/dnssniff-core/src/net_proto/mod.rs` (Create)
*   **Type / Scope**: Network & Transport Layer Decoder
*   **Proposed Changes**: Implement IPv4/IPv6 and UDP header parsing on borrowed byte slices. Extract 5-tuple (`client_ip`, `server_ip`, `client_port`, `server_port`), verify UDP length, and compute the subslice offset where the DNS wire payload begins (`&buf[ip_header_len + 8..]`).

#### 8. `crates/dnssniff-core/src/dns_proto/mod.rs` (Create)
*   **Type / Scope**: DNS Protocol Module Root
*   **Proposed Changes**: Re-export header flags, record structures, and wire parsing functions.

#### 9. `crates/dnssniff-core/src/dns_proto/header.rs` (Create)
*   **Type / Scope**: Zero-Copy Header Decoder
*   **Proposed Changes**: Parse 12-byte RFC 1035 headers directly from `&[u8]`. Decode 16-bit Transaction ID, flags (QR, Opcode, AA, TC, RD, RA, RCODE), and record counts (QDCOUNT, ANCOUNT).

#### 10. `crates/dnssniff-core/src/dns_proto/parser.rs` (Create)
*   **Type / Scope**: Safe Zero-Alloc Wire Parser
*   **Proposed Changes**: Implement `parse_dns_message(buf: &[u8])`. Extract QNAME, QTYPE, QCLASS, and record answers on borrowed byte slices. Implement strict pointer validation on compression pointers (`(byte[0] & 0xC0) == 0xC0`) enforcing a 16-hop recursion bound to eliminate denial-of-service loops while supporting deeply nested CNAMEs.

#### 11. `crates/dnssniff-core/src/tracker/mod.rs` (Create)
*   **Type / Scope**: Tracker Module Root
*   **Proposed Changes**: Expose `TransactionTracker` and timeout configurations.

#### 12. `crates/dnssniff-core/src/tracker/matching.rs` (Create)
*   **Type / Scope**: Transaction Matching Engine
*   **Proposed Changes**: Implement fixed-capacity 8,192-slot table keyed by `TransactionKey` (5-tuple + interface index). Manage a monotonic generation-indexed FIFO timeout queue `VecDeque<(Instant, u32, u64)>` for $O(1)$ lazy timeout eviction without $O(N)$ memory shifts or ABA hazards. Match queries with responses to compute latency in microseconds (`rtt_us`).

#### 13. `crates/dnssniff-core/src/ring/mod.rs` (Create)
*   **Type / Scope**: Bounded Circular Ring Buffers
*   **Proposed Changes**: Implement `CircularRingBuffer<TransactionSummary, 1000>` for live and error transaction streams with 64-byte inline domain storage and a 64 KB extended domain string arena.

#### 14. `crates/dnssniff-web/Cargo.toml` (Create)
*   **Type / Scope**: Portable Web Server Manifest
*   **Proposed Changes**: Declare dependencies on `dnssniff-core`, `mio = "0.8"`, `httparse = "1.8"`. Keep dependencies isolated from GUI or CLI code to enable easy reuse in external DNS projects.

#### 15. `crates/dnssniff-web/src/lib.rs` (Create)
*   **Type / Scope**: Web Server Library Root
*   **Proposed Changes**: Export `HttpServer` and the `DnsTelemetrySource` consumer trait.

#### 16. `crates/dnssniff-web/src/server.rs` (Create)
*   **Type / Scope**: Non-Blocking HTTP Reactor
*   **Proposed Changes**: Implement non-blocking `TcpListener` using `httparse` handling HTTP `GET /`, `GET /stats`, `GET /events`, `GET /export.json`, and `GET /health`. Inject safe LAN CORS headers.

#### 17. `crates/dnssniff-web/src/sse.rs` (Create)
*   **Type / Scope**: Server-Sent Events Broadcaster
*   **Proposed Changes**: Stream newline-delimited `data: {...}\n\n` JSON transaction events to connected browser clients over persistent non-blocking HTTP connections with lossy drop policies for slow consumers.

#### 18. `crates/dnssniff-web/src/stats_json.rs` (Create)
*   **Type / Scope**: Zero-Alloc JSON Formatter & Logarithmic Histogram
*   **Proposed Changes**: Implement a fixed 64-bucket logarithmic histogram (HDR histogram) updated in $O(1)$ time upon transaction completion. Format JSON directly via `write!` macro into a 2 KB scratch buffer for `GET /stats`.

#### 19. `crates/dnssniff-web/assets/index.html` (Create)
*   **Type / Scope**: Embedded Single-Page Web Dashboard
*   **Proposed Changes**: Self-contained HTML5/CSS/JS file (< 20 KB) with split-window layout: top table showing live transactions with status indicators, view toggle for the error buffer, and bottom pane showing detailed decoded DNS flags and records. Connects via `EventSource('/events')`.

#### 20. `crates/dnssniff-cli/Cargo.toml` (Create)
*   **Type / Scope**: CLI Daemon Binary Manifest
*   **Proposed Changes**: Binary crate depending on `dnssniff-core` and `dnssniff-web`.

#### 21. `crates/dnssniff-cli/src/main.rs` (Create)
*   **Type / Scope**: Application Entrypoint
*   **Proposed Changes**: Parse CLI flags (`-i <interface>`, `--timeout <secs>`, `--http-port <port>`, `--http-host <addr>`). Initialize signal handlers for clean shutdown (`SIGINT`, `SIGTERM`). Run the single-threaded event loop coordinating raw packet ingestion, timeout sweeping, and HTTP client I/O.

#### 22. `crates/dnssniff-wasm/Cargo.toml` (Create)
*   **Type / Scope**: Offline-Capable WebAssembly Crate Manifest
*   **Proposed Changes**: Configure crate-type `cdylib`, depending on `wasm-bindgen = "0.2"`, `web-sys`, and `js-sys`.

#### 23. `crates/dnssniff-wasm/src/lib.rs` (Create)
*   **Type / Scope**: In-Browser Analytics Engine
*   **Proposed Changes**: Implement browser-based analytics engine loadable via local HTTP or snapshot import. Match full domain names against an in-browser `HashSet<String>` ad-server blocklist and compute sliding-window latency distributions.

#### 24. `openwrt/Makefile` (Create)
*   **Type / Scope**: OpenWrt Package Feed Recipe
*   **Proposed Changes**: Define package metadata (`PKG_NAME:=dnssniff`), install targets into `/usr/bin/dnssniff`, and configure musl cross-compilation toolchain flags.

#### 25. `openwrt/files/dnssniff.config` (Create)
*   **Type / Scope**: OpenWrt UCI Configuration
*   **Proposed Changes**: Default UCI settings (`config dnssniff 'main'`, `option interface 'br-lan'`, `option http_port '9153'`, `option enabled '1'`).

#### 26. `openwrt/files/dnssniff.init` (Create)
*   **Type / Scope**: OpenWrt `procd` Service Script
*   **Proposed Changes**: Standard init script starting `dnssniff` under `procd` with auto-restart, stdout redirected to logd, and clean signal termination.

#### 27. `README.md` (Modify)
*   **Type / Scope**: Repository Blueprint Contract
*   **Proposed Changes**: Update component descriptions, build commands (`cargo build --release`), verification targets, and execution options.

---

### Verification Plan

*   **Compilation/Build**:
    *   Host target: `cargo build --workspace`
    *   Static musl target: `cargo build --workspace --target x86_64-unknown-linux-musl --release`
    *   WASM target: `wasm-pack build crates/dnssniff-wasm --target web`
*   **Unit Tests**:
    *   Run: `cargo test --workspace`
    *   `net_proto`: Verify IPv4, IPv6, and UDP header parsing and slice offset calculation.
    *   `dns_proto`: Verify header decoding, record parsing, and cyclic compression pointer rejection (16-hop threshold).
    *   `tracker`: Verify 5-tuple matching, response pairing, RTT calculation, generation-indexed lazy FIFO 3.0s timeout eviction, and ABA prevention.
    *   `ring`: Verify circular buffer overwriting and 1,000-entry capacity invariants.
    *   `stats_json`: Validate JSON syntax, logarithmic histogram calculation, and sub-2ms serialization.
*   **Static Analysis & Linting**:
    *   Run: `cargo clippy --workspace -- -D warnings`
    *   Run: `cargo fmt --all -- --check`
*   **Binary Size Verification**:
    *   Verify stripped release binary `target/x86_64-unknown-linux-musl/release/dnssniff` is strictly **< 650 KB**.
*   **Integration & Live Sniffing Verification**:
    *   Execute `dnssniff -i lo --http-port 9153` in sandbox.
    *   Issue test queries: `dig @127.0.0.1 -p 53 example.com` and simulate timeout drops.
    *   Verify `curl http://127.0.0.1:9153/stats` returns valid JSON with updated counters.
    *   Verify `curl http://127.0.0.1:9153/events` delivers properly formatted Server-Sent Events.

--------------------------------------------------------------------------------

*Drafted with EGM*
