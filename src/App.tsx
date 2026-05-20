import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";

interface ScanLog {
  id: number;
  ssid: string;
  domain: string;
  risk_score: number;
  risk_level: string;
  reason: string;
  created_at: string;
}

interface TrustedNetwork {
  id: number;
  ssid: string;
  bssid: string | null;
  created_at: string;
}

export default function App() {
  const [logs, setLogs] = useState<ScanLog[]>([]);
  const [trusted, setTrusted] = useState<TrustedNetwork[]>([]);
  const [currentSsid, setCurrentSsid] = useState<string | null>(null);

  async function refresh() {
    try {
      const [l, t, ssid] = await Promise.all([
        invoke<ScanLog[]>("get_scan_logs"),
        invoke<TrustedNetwork[]>("get_trusted_networks"),
        invoke<string | null>("get_current_ssid"),
      ]);
      setLogs(l);
      setTrusted(t);
      setCurrentSsid(ssid);
    } catch (e) {
      console.error(e);
    }
  }

  useEffect(() => {
    refresh();
    const interval = setInterval(refresh, 5000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="container">
      <header>
        <div
          className="status-dot"
          style={{
            background:
              logs.length > 0
                ? getStatusColor(logs[0].risk_level)
                : "#888",
          }}
        />
        <h1>Fake WiFi Portal Detector</h1>
      </header>

      <section>
        <h2>Current Network</h2>
        <p className="ssid">{currentSsid || "Not connected"}</p>
      </section>

      <section>
        <h2>Trusted Networks</h2>
        <ul>
          {trusted.length === 0 ? (
            <li className="empty">No trusted networks</li>
          ) : (
            trusted.map((t) => <li key={t.id}>{t.ssid}</li>)
          )}
        </ul>
      </section>

      <section>
        <h2>Scan History</h2>
        <div className="log-list">
          {logs.length === 0 ? (
            <p className="empty">No scan data yet</p>
          ) : (
            logs.map((log) => (
              <div key={log.id} className="log-entry">
                <div className="log-header">
                  <span className="log-ssid">{log.ssid}</span>
                  <span
                    className="log-score"
                    style={{ color: getStatusColor(log.risk_level) }}
                  >
                    {log.risk_level} ({log.risk_score})
                  </span>
                </div>
                <div className="log-reason">
                  {log.reason || "No issues"}
                </div>
                <div className="log-time">{log.created_at}</div>
              </div>
            ))
          )}
        </div>
      </section>
    </div>
  );
}

function getStatusColor(level: string): string {
  switch (level) {
    case "Safe":
      return "#00d4aa";
    case "Suspicious":
      return "#ffd700";
    case "High Risk":
      return "#ff8800";
    case "Critical":
      return "#ff4444";
    default:
      return "#888";
  }
}
