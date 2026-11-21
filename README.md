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

## Latency Histogram

Latency is calculated per DNS query+response transaction:

1. **Query capture**: When a DNS query packet is captured, its timestamp (milliseconds since Unix epoch) is stored in a pending-query tracker.
2. **Response capture**: When the matching DNS response arrives (matched by Transaction ID + 5-tuple + interface index), RTT is computed as `response_timestamp_ms - query_timestamp_ms`.
3. **Bucketing**: Each RTT value (in microseconds) is inserted into a **64-bucket logarithmic histogram** spanning 100 µs to 10 seconds:

   ```
   bucket = log2(latency_us / 100) / log2(100000) * 63
   ```

   - Bucket 0: ≤ 100 µs (sub-millisecond)
   - Buckets 1-62: logarithmically spaced
   - Bucket 63: ≥ 10 seconds

4. **Percentiles** (`p50`, `p90`, `p99`): The histogram walks buckets cumulatively until `cumulative_count >= total_count * p`, then returns the approximate bucket center as the percentile value.
5. **Average**: `sum_us / count`.

If most DNS responses complete under 100 µs, all values fall into bucket 0 and percentiles will show ~100 µs — indicating very fast DNS resolution.

## Testing

```bash
cargo test --workspace
```

Unit tests cover: IPv4/IPv6/UDP parsing, DNS header decoding, compression pointer safety (16-hop limit), transaction matching, timeout eviction, ring buffer invariants, and histogram/JSON serialization.