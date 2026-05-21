# Fake WiFi Portal Detector

A lightweight Linux desktop application that monitors WiFi networks and detects fake captive portals, phishing login pages, suspicious redirects, and SSL/TLS anomalies on public WiFi.

## Features

- **Network Monitoring** — automatic detection of WiFi SSID and gateway changes
- **Captive Portal Detection** — probes known endpoints to detect portal interception
- **SSL/TLS Validation** — certificate validation, expiry checks, hostname matching, self-signed detection
- **Redirect Analysis** — chain depth, IP redirects, suspicious TLDs, HTTP→HTTPS downgrade, loop detection
- **Login Page Heuristics** — password field detection, domain consistency, branding analysis, hidden input detection, urgency text analysis
- **Risk Scoring** — weighted scoring (Safe / Suspicious / High Risk / Critical) with 10 factors
- **Desktop Notifications** — non-duplicate alerts with severity levels, recommended actions
- **Trusted Networks** — per-SSID whitelist with SQLite persistence
- **Local History** — scan logs stored in SQLite for review

## Architecture

```
Network Monitor → Probe Engine → TLS Validator → Redirect Analyzer → Login Analyzer
                                                              ↓
                                                       Risk Engine
                                                              ↓
                                                   ┌──────┴──────┐
                                                   │             │
                                               Tray UI      SQLite Logs
                                              (Tauri)       (rusqlite)
```

## Quick Start

### Prerequisites

| Dependency | Version |
|---|---|
| Rust | 1.75+ |
| Node.js | 20+ |
| npm | 9+ |
| Linux | NetworkManager (nmcli) |

System libraries (install if missing):
```bash
# Ubuntu/Debian
sudo apt install libgtk-3-0 libwebkit2gtk-4.1-0 libjavascriptcoregtk-4.1-0 libappindicator3-1

# Fedora
sudo dnf install gtk3 webkit2gtk4.1 libappindicator-gtk3

# Arch
sudo pacman -S gtk3 webkit2gtk libappindicator-gtk3
```

### Build & Run

```bash
# Install frontend dependencies
npm install

# Development mode
npm run tauri dev

# Production build
npm run tauri build
```

### Package

Build creates AppImage, .deb, and .rpm packages:
```bash
npm run tauri build
```

Output: `src-tauri/target/release/bundle/`

## Configuration

Edit `configs/default.toml` to customize:

```toml
[general]
check_interval_secs = 30          # Network poll interval

[probe]
targets = ["https://..."]          # Probe endpoints
timeout_secs = 5                   # Request timeout

[tls]
require_valid_cert = true          # Reject invalid certs
warn_self_signed = true            # Warn on self-signed

[redirect]
max_depth = 10                     # Max redirect chain length
suspicious_tlds = ["tk", "ml"]     # TLDs to flag

[scoring]
weights = { invalid_ssl = 40 }     # Custom scoring weights

[database]
max_records = 10000                # Max stored scan logs
```

Config search order:
1. `configs/default.toml` (project root)
2. `$BINDIR/configs/default.toml`
3. `/etc/fakewifi-detector/config.toml`

## Project Structure

```
src-tauri/
├── src/
│   ├── main.rs              # Binary entry point
│   ├── lib.rs               # Tauri setup, commands, scan orchestrator
│   ├── config/mod.rs        # TOML-based configuration
│   ├── database/mod.rs      # SQLite (trusted_networks, scan_logs, app_settings)
│   ├── network/mod.rs       # nmcli-based WiFi monitoring
│   ├── probe/mod.rs         # Captive portal probe engine
│   ├── tls/mod.rs           # reqwest/rustls TLS validation
│   ├── redirect/mod.rs      # Redirect chain analysis
│   ├── login_analyzer/mod.rs# Login page phishing detection
│   ├── scoring/mod.rs       # Weighted risk scoring engine
│   ├── notifications/mod.rs # Desktop notification system
│   └── logging/mod.rs       # tracing + file rotation logging
├── tests/
│   └── scan_pipeline_test.rs# Integration tests
└── Cargo.toml

src/                          # Frontend (React + TypeScript + Tauri)
├── main.tsx
├── App.tsx
├── styles.css
└── tray/tray.ts
```

## Testing

```bash
cargo test                    # Unit + integration tests
```

Includes tests for:
- Scoring engine (weights, thresholds, breakdowns)
- Redirect analyzer (TLD, IP, domain switch, URL resolution)
- Login analyzer (password, branding, hidden inputs, form actions)
- TLS validator (error handling, unknown hosts)
- Database CRUD (trusted networks, scan logs, settings)
- Network monitor (nmcli output parsing)
- Notifications (content creation, dedup)
- Full pipeline integration

## Threat Coverage

| Threat | Detection |
|---|---|
| Evil Twin AP | SSID/gateway monitoring |
| Fake Captive Portal | Probe response analysis |
| SSL Stripping | TLS validation |
| Redirect Hijacking | Chain analysis |
| Phishing Login | HTML heuristics |
| Self-Signed Cert | Certificate validation |

## License

MIT
