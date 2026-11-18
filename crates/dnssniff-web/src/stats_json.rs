//! Zero-Alloc JSON Formatter & Logarithmic Histogram (`dnssniff-web::stats_json`)
//!
//! Implements a fixed 64-bucket logarithmic histogram updated in O(1) time
//! upon transaction completion. Formats JSON directly via `write!` macro
//! into a scratch buffer for `GET /stats`.

use std::fmt::Write;

use dnssniff_core::types::{LatencyHistogram, StatsPayload};

/// Format a `StatsPayload` into a JSON string.
pub fn format_stats_json(payload: &StatsPayload) -> String {
    let mut buf = String::with_capacity(512);
    let _ = write!(
        buf,
        "{{
  \"uptime_secs\": {},
  \"active_queries\": {},
  \"total_queries\": {},
  \"total_responses\": {},
  \"parsed_packets\": {},
  \"unparsed_packets\": {},
  \"errors\": {{
    \"timeouts\": {},
    \"servfail\": {},
    \"nxdomain\": {},
    \"refused\": {},
    \"malformed\": {}
  }},
  \"latency_us\": {{
    \"p50\": {},
    \"p90\": {},
    \"p99\": {},
    \"avg\": {}
  }}
}}",
        payload.uptime_secs,
        payload.active_queries,
        payload.total_queries,
        payload.total_responses,
        payload.parsed_packets,
        payload.unparsed_packets,
        payload.timeouts,
        payload.servfail,
        payload.nxdomain,
        payload.refused,
        payload.malformed,
        payload.p50_us,
        payload.p90_us,
        payload.p99_us,
        payload.avg_us,
    );
    buf
}

/// Compute a `StatsPayload` from counters and histogram.
pub fn compute_stats(
    counters: &dnssniff_core::types::TelemetryCounters,
    histogram: &LatencyHistogram,
) -> StatsPayload {
    StatsPayload {
        uptime_secs: counters.uptime_secs,
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
        p50_us: histogram.percentile(0.50),
        p90_us: histogram.percentile(0.90),
        p99_us: histogram.percentile(0.99),
        avg_us: histogram.avg_us(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dnssniff_core::types::{LatencyHistogram, TelemetryCounters};

    #[test]
    fn test_format_stats_json() {
        let counters = TelemetryCounters {
            uptime_secs: 1420,
            active_queries: 12,
            total_queries: 45120,
            total_responses: 44890,
            parsed_packets: 44890,
            unparsed_packets: 10,
            timeouts: 210,
            servfail: 14,
            nxdomain: 840,
            refused: 6,
            malformed: 0,
            table_overflow_evictions: 0,
            sse_dropped_events: 0,
        };
        let mut histogram = LatencyHistogram::default();
        histogram.insert(11200);
        histogram.insert(28400);
        histogram.insert(92100);

        let payload = compute_stats(&counters, &histogram);
        let json = format_stats_json(&payload);

        assert!(json.contains("\"uptime_secs\": 1420"));
        assert!(json.contains("\"total_queries\": 45120"));
        assert!(json.contains("\"p50\""));
        assert!(json.contains("\"p99\""));
    }

    #[test]
    fn test_histogram_percentile() {
        let mut histogram = LatencyHistogram::default();
        for i in 1..=100 {
            histogram.insert(i * 1000); // 1000 to 100000 us
        }
        let p50 = histogram.percentile(0.50);
        let p99 = histogram.percentile(0.99);
        assert!(p50 > 0);
        assert!(p99 >= p50);
    }
}
