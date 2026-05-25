// =========================================================
// config.rs — EasyWAF
// Loads TOML configuration from config.toml at startup.
// =========================================================

use serde::Deserialize;
use std::fs;

// ─── Config ──────────────────────────────────────────────

#[derive(Deserialize, Clone, Debug)]
pub struct Config {
    pub secret:       String,
    pub database_url: String,
    pub proxy:        ProxyConfig,
}

// ─── ProxyConfig ─────────────────────────────────────────

#[derive(Deserialize, Clone, Debug)]
pub struct ProxyConfig {
    /// Port for the reverse proxy (HTTP). Default: 80.
    pub http_port:  u16,
    /// Port for the management GUI. Default: 8080.
    pub gui_port:   u16,
    /// Optional: path to the MaxMind GeoLite2-Country.mmdb file.
    pub geoip_db:   Option<String>,
    /// Directory for ACME HTTP-01 challenge files.
    pub acme_webroot: Option<String>,
}

// ─── load ────────────────────────────────────────────────

pub fn load(path: &str) -> Config {
    let text = fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("Cannot read config file '{}': {}", path, e));
    toml::from_str(&text)
        .unwrap_or_else(|e| panic!("Cannot parse config file '{}': {}", path, e))
}
