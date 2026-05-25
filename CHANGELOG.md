# Changelog

All notable changes to EasyWAF are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Version bumps and tags are created only after explicit approval.

---

## [Unreleased]

### Added
- **Traffic Monitor** (`GET /traffic`) — live view of every proxied request with:
  - Filter bar: site, blocked/allowed/all, time window (1 h – 30 d)
  - Four stat cards: total requests, blocked, allowed, average response time
  - Stacked bar chart (Chart.js) showing allowed vs blocked requests per hour
  - DataTables event log (up to 1000 rows) with method colour-coding,
    status-code colour-coding, country, and block-reason tooltip
  - Live-refresh toggle (auto-reloads every 5 s)
- Traffic Monitor link added to the sidebar navigation

### Fixed
- `sites.html` — removed stale `site.port` and `site.waf_policy` references
  that caused a template render error; replaced with `site.waf_policy_id`
  badge and `site.enabled` status badge

---

## [0.1.0] — 2025-05-25 (initial Rust rewrite)

### Added
- Self-contained HTTP reverse proxy (no nginx dependency)
- Virtual hosting routed by `Host:` header
- Management GUI on a separate port (Axum + Tera)
- SQLite database with WAL mode, auto-created on first run
- Module pipeline: async inspection modules (Pass / Alert / Block)
- TrafficLogger module — every proxied request written to `traffic_events`
- Site management: create, edit, delete virtual hosts
- Certificate management: PEM stored in DB
- WAF policy management
- GeoIP rules UI
- Dashboard with 24 h traffic summary
- Default `admin/admin` account seeded on first run
