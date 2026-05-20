#!/usr/bin/env bash
set -euo pipefail

echo "=== Fake WiFi Portal Detector Build ==="

echo ""
echo "[1/4] Installing frontend dependencies..."
npm install

echo ""
echo "[2/4] Building frontend..."
npm run build

echo ""
echo "[3/4] Building Tauri app..."
npm run tauri build

echo ""
echo "[4/4] Done!"
echo "Binary available at: src-tauri/target/release/fakewifi-detector"
