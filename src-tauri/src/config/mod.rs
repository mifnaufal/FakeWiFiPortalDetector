use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub general: GeneralConfig,
    pub probe: ProbeConfig,
    pub tls: TlsConfig,
    pub redirect: RedirectConfig,
    pub scoring: ScoringConfig,
    pub notifications: NotificationConfig,
    pub database: DatabaseConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralConfig {
    pub check_interval_secs: u64,
    pub notification_timeout_secs: u64,
    pub enable_tray: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeConfig {
    pub targets: Vec<String>,
    pub timeout_secs: u64,
    pub expected_http_probe: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    pub require_valid_cert: bool,
    pub warn_self_signed: bool,
    pub warn_expired: bool,
    pub warn_hostname_mismatch: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedirectConfig {
    pub max_depth: u32,
    pub suspicious_tlds: Vec<String>,
    pub suspicious_keywords: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoringConfig {
    pub weights: std::collections::HashMap<String, i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationConfig {
    pub enabled: bool,
    pub show_detailed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub path: String,
    pub max_records: i64,
}

impl Default for AppConfig {
    fn default() -> Self {
        AppConfig {
            general: GeneralConfig {
                check_interval_secs: 30,
                notification_timeout_secs: 10,
                enable_tray: true,
            },
            probe: ProbeConfig {
                targets: vec![
                    "https://captive.g.apple.com/hotspot-detect.html".to_string(),
                    "https://nmcheck.gnome.org/check_network_status.txt".to_string(),
                    "http://connectivitycheck.platform.hmms.gov.cn/generate_204".to_string(),
                ],
                timeout_secs: 5,
                expected_http_probe: "HTTP 204".to_string(),
            },
            tls: TlsConfig {
                require_valid_cert: true,
                warn_self_signed: true,
                warn_expired: true,
                warn_hostname_mismatch: true,
            },
            redirect: RedirectConfig {
                max_depth: 10,
                suspicious_tlds: vec![
                    "tk".to_string(), "ml".to_string(), "ga".to_string(),
                    "cf".to_string(), "gq".to_string(), "xyz".to_string(),
                    "top".to_string(), "club".to_string(),
                ],
                suspicious_keywords: vec![
                    "login".to_string(), "signin".to_string(), "verify".to_string(),
                    "account".to_string(), "update".to_string(), "secure".to_string(),
                ],
            },
            scoring: ScoringConfig {
                weights: [
                    ("invalid_ssl".to_string(), 40),
                    ("hostname_mismatch".to_string(), 35),
                    ("suspicious_redirect".to_string(), 25),
                    ("phishing_login_page".to_string(), 30),
                    ("trusted_network_discount".to_string(), -50),
                ]
                .iter()
                .cloned()
                .collect(),
            },
            notifications: NotificationConfig {
                enabled: true,
                show_detailed: true,
            },
            database: DatabaseConfig {
                path: "~/.local/share/fakewifi-detector/history.db".to_string(),
                max_records: 10000,
            },
        }
    }
}

impl AppConfig {
    pub fn load(path: Option<PathBuf>) -> Self {
        let path = path.unwrap_or_else(|| {
            let exe_dir = std::env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(|p| p.to_path_buf()));
            let paths = [
                exe_dir.clone().map(|p| p.join("configs/default.toml")),
                Some(PathBuf::from("configs/default.toml")),
                Some(PathBuf::from("/etc/fakewifi-detector/config.toml")),
            ];
            paths
                .iter()
                .flatten()
                .find(|p| p.exists())
                .cloned()
                .unwrap_or_else(|| PathBuf::from("configs/default.toml"))
        });

        match std::fs::read_to_string(&path) {
            Ok(content) => match toml::from_str(&content) {
                Ok(config) => {
                    tracing::info!("Loaded config from {}", path.display());
                    config
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to parse config at {}: {}; using defaults",
                        path.display(),
                        e
                    );
                    AppConfig::default()
                }
            },
            Err(_) => {
                tracing::info!("No config at {}; using defaults", path.display());
                AppConfig::default()
            }
        }
    }

    pub fn database_path(&self) -> PathBuf {
        let p = self.database.path.replace('~', &std::env::var("HOME").unwrap_or_default());
        PathBuf::from(p)
    }
}
