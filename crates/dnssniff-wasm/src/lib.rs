//! # dnssniff-wasm
//!
//! Offline-capable WebAssembly analytics suite for dnssniff.
//!
//! Loadable via local HTTP from the router or as a local desktop HTML/WASM
//! bundle. Provides in-browser ad-server blocklist matching, latency
//! histogram computation, and autonomous network grouping.

use wasm_bindgen::prelude::*;
use js_sys::Set;

#[wasm_bindgen]
pub struct DnsAnalytics {
    ad_server_set: Set,
}

#[wasm_bindgen]
impl DnsAnalytics {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            ad_server_set: Set::new(),
        }
    }

    /// Load ad-server domains into the blocklist hash set.
    pub fn load_ad_servers(&mut self, domains: js_sys::Array) {
        let set = Set::new();
        for i in 0..domains.length() {
            if let Some(domain) = domains.get(i).as_string() {
                set.add(&domain.into());
            }
        }
        self.ad_server_set = set;
    }

    /// Check if a domain matches an ad/tracker server.
    pub fn is_ad_server(&self, domain: &str) -> bool {
        self.ad_server_set.has(&domain.into())
    }

    /// Compute a simple latency bucket index (logarithmic).
    pub fn latency_bucket(latency_us: f64) -> u32 {
        if latency_us <= 100.0 {
            return 0;
        }
        if latency_us >= 10_000_000.0 {
            return 63;
        }
        ((latency_us / 100.0).log2() / (100_000.0f64).log2() * 63.0) as u32
    }
}

#[wasm_bindgen]
pub fn analyze_domains(domains: js_sys::Array, ad_servers: js_sys::Array) -> js_sys::Object {
    let analytics = DnsAnalytics::new();
    analytics.load_ad_servers(ad_servers);

    let result = js_sys::Object::new();
    let _ = js_sys::Reflect::set(&result, &"total".into(), &(domains.length() as f64));

    let ad_count = (0..domains.length())
        .filter(|i| {
            if let Some(d) = domains.get(*i).as_string() {
                analytics.is_ad_server(&d)
            } else {
                false
            }
        })
        .count();

    let _ = js_sys::Reflect::set(&result, &"adCount".into(), &(ad_count as f64));
    let _ = js_sys::Reflect::set(
        &result,
        &"adRatio".into(),
        &(if domains.length() > 0 {
            ad_count as f64 / domains.length() as f64
        } else {
            0.0
        }),
    );

    result
}
