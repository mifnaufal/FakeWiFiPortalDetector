use serde::{Deserialize, Serialize};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;
use tracing::{info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInfo {
    pub ssid: Option<String>,
    pub gateway: Option<String>,
    pub interface: Option<String>,
}

#[derive(Debug)]
pub enum NetworkEvent {
    Connected(NetworkInfo),
    Disconnected,
    SsidChanged(String, String),
}

pub struct NetworkMonitor {
    tx: mpsc::Sender<NetworkEvent>,
    rx: mpsc::Receiver<NetworkEvent>,
}

impl NetworkMonitor {
    pub fn new() -> Self {
        let (tx, rx) = mpsc::channel();
        NetworkMonitor { tx, rx }
    }

    pub fn start(&self) {
        let tx = self.tx.clone();
        thread::spawn(move || {
            let mut last_ssid: Option<String> = None;

            loop {
                let current = Self::get_current_network();

                match (&current, &last_ssid) {
                    (Some(info), None) => {
                        info!("Network connected: {:?}", info.ssid);
                        tx.send(NetworkEvent::Connected(info.clone())).ok();
                    }
                    (None, Some(_)) => {
                        info!("Network disconnected");
                        tx.send(NetworkEvent::Disconnected).ok();
                    }
                    (Some(curr), Some(prev_ssid)) => {
                        if curr.ssid.as_deref() != Some(prev_ssid) {
                            let old = prev_ssid.clone();
                            let new = curr.ssid.clone().unwrap_or_default();
                            info!("SSID changed: {} -> {}", old, new);
                            tx.send(NetworkEvent::SsidChanged(old, new)).ok();
                            tx.send(NetworkEvent::Connected(curr.clone())).ok();
                        }
                    }
                    _ => {}
                }

                last_ssid = current.and_then(|c| c.ssid.clone());
                thread::sleep(Duration::from_secs(5));
            }
        });
    }

    pub fn get_receiver(&self) -> mpsc::Receiver<NetworkEvent> {
        self.rx.clone()
    }

    pub fn parse_nmcli_output(output: &str) -> Option<NetworkInfo> {
        for line in output.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 3 {
                let ssid = parts[0].to_string();
                let gateway = parts[1].to_string();
                let interface = parts[2].to_string();
                if !ssid.is_empty() {
                    return Some(NetworkInfo {
                        ssid: Some(ssid),
                        gateway: Some(gateway),
                        interface: Some(interface),
                    });
                }
            }
        }
        None
    }

    fn get_current_network() -> Option<NetworkInfo> {
        let output = std::process::Command::new("nmcli")
            .args(["-t", "-f", "SSID,GATEWAY,DEVICE", "connection", "show", "--active"])
            .output()
            .ok()?;

        if !output.status.success() {
            warn!("nmcli command failed");
            return None;
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        Self::parse_nmcli_output(&stdout)
    }

    pub fn get_ssid() -> Option<String> {
        Self::get_current_network().and_then(|n| n.ssid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_nmcli_output_valid() {
        let output = "HomeWiFi:192.168.1.1:wlan0\n";
        let info = NetworkMonitor::parse_nmcli_output(output);
        assert!(info.is_some());
        let info = info.unwrap();
        assert_eq!(info.ssid, Some("HomeWiFi".to_string()));
        assert_eq!(info.gateway, Some("192.168.1.1".to_string()));
        assert_eq!(info.interface, Some("wlan0".to_string()));
    }

    #[test]
    fn test_parse_nmcli_output_no_ssid() {
        let output = "::wlan0\n";
        let info = NetworkMonitor::parse_nmcli_output(output);
        assert!(info.is_none());
    }

    #[test]
    fn test_parse_nmcli_output_multiple() {
        let output = "NetA:10.0.0.1:wlan0\nNetB:10.0.0.2:wlan0\n";
        let info = NetworkMonitor::parse_nmcli_output(output).unwrap();
        assert_eq!(info.ssid, Some("NetA".to_string()));
    }

    #[test]
    fn test_parse_nmcli_output_empty() {
        assert!(NetworkMonitor::parse_nmcli_output("").is_none());
    }

    #[test]
    fn test_network_info_serialization() {
        let info = NetworkInfo {
            ssid: Some("Test".to_string()),
            gateway: Some("1.1.1.1".to_string()),
            interface: Some("eth0".to_string()),
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("Test"));
        assert!(json.contains("1.1.1.1"));
    }
}
