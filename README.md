# Fake WiFi Portal Detector

A lightweight Linux desktop application that monitors WiFi networks and detects fake captive portals, phishing login pages, suspicious redirects, and SSL/TLS anomalies.

## Features

- **Network Monitoring** — automatic detection of WiFi connection changes
- **Captive Portal Detection** — probe requests to detect portal interception
- **SSL/TLS Validation** — certificate chain, hostname matching, expiry checks
- **Redirect Analysis** — chain depth, IP redirects, suspicious TLDs
- **Login Page Heuristics** — form detection, password fields, HTTPS consistency
- **Risk Scoring** — weighted scoring with Safe / Suspicious / High Risk / Critical levels
- **Desktop Notifications** — real-time alerts with actionable buttons
- **Trusted Networks** — whitelist to reduce false positives
- **Local History** — SQLite-backed event log

## Architecture

```text
Network Monitor → Probe Engine → TLS Validator → Redirect Analyzer
                                                      ↓
                                               Risk Scorer
                                                      ↓
                                              Policy Engine
                                             /              \
                                        Tray UI        SQLite Logs
```

## Quick Start

### Prerequisites

- Rust 1.75+
- Node.js 20+
- Linux with NetworkManager (DBus)

### Build & Run

```bash
npm install
npm run tauri dev
```

### Package

```bash
npm run tauri build
```

## Configuration

See `configs/default.toml` for available settings.

## License

MIT
