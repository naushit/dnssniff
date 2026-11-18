# dnssniff: Lightweight Embedded DNS Sniffer & Web Telemetry for OpenWrt

`dnssniff` is a lightweight, zero-persistence DNS packet sniffer and diagnostic telemetry tool written in Rust for resource-constrained embedded Linux environments, specifically OpenWrt routers.

## Architecture

The repository is organized as a Cargo workspace with four crates:

| Crate | Purpose |
|-------|---------|
| `dnssniff-core` | Packet capture (AF_PACKET + cBPF), protocol parsing (IPv4/IPv6/UDP/DNS), transaction tracking, ring buffers |
| `dnssniff-web` | Portable HTTP & SSE server with JSON telemetry endpoints |
| `dnssniff-cli` | CLI daemon binary - entrypoint that ties capture + web together |
| `dnssniff-wasm` | Offline-capable WebAssembly analytics suite (stub) |

## Design

The full design is documented in `docs/designs/dnssniff.md`.

Key design decisions:
- **Zero external C dependencies**: Uses Linux `AF_PACKET` raw sockets with in-kernel cBPF filters instead of `libpcap`
- **Zero disk persistence**: All state in RAM, no flash writes
- **Bounded memory**: Pre-allocated ring buffers (1000 entries each), fixed 8192-slot tracker table, < 32 MB RSS ceiling
- **Sub-megabyte binary**: ~500 KB stripped static musl binary
- **Offline-first web dashboard**: Embedded <20 KB SPA served from the binary
- **Server-Sent Events**: Real-time telemetry streaming to browser

## Build

```bash
# Host build
cargo build --release

# Static musl build (for OpenWrt cross-compilation)
cargo build --release --target x86_64-unknown-linux-musl

# Run tests
cargo test --workspace

# Clippy
cargo clippy --workspace -- -D warnings
```

## Run

```bash
# Requires CAP_NET_RAW (root) for AF_PACKET raw socket
sudo ./target/release/dnssniff-cli -i br-lan --http-port 9153

# Then open http://router-ip:9153/ in a browser
```

Endpoints:
- `GET /` - Embedded web dashboard
- `GET /stats` - JSON metrics (query rates, latency percentiles, error counts)
- `GET /events` - Server-Sent Events stream
- `GET /export.json` - Full JSON snapshot of transactions
- `GET /health` - Liveness check

## CLI Options

```
-i, --interface <iface>  Network interface (br-lan, eth0, or 'any') [default: any]
--timeout <secs>         DNS query timeout in seconds [default: 3]
--http-port <port>       HTTP server listen port [default: 9153]
--http-host <addr>       HTTP server listen address [default: 0.0.0.0]
```

## OpenWrt Packaging

See `openwrt/Makefile` for the OpenWrt package feed recipe, including UCI config and procd init script.

## Memory Budget

| Subsystem | Max Footprint |
|-----------|---------------|
| Ingress stack frame | 4 KB |
| In-flight tracker (8192 slots) | 393 KB |
| FIFO timeout queue | 256 KB |
| Live ring (1000 entries) | 128 KB |
| Error ring (1000 entries) | 128 KB |
| Domain arena | 64 KB |
| Latency histogram (64 buckets) | 0.5 KB |
| **Typical RSS** | **~5.2 - 6.8 MB** |
| **Absolute ceiling** | **< 32 MB** |

## Testing

```bash
cargo test --workspace
```

Unit tests cover: IPv4/IPv6/UDP parsing, DNS header decoding, compression pointer safety (16-hop limit), transaction matching, timeout eviction, ring buffer invariants, and histogram/JSON serialization.