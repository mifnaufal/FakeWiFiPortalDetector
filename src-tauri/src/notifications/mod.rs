use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Mutex;
use tauri::AppHandle;
use tauri_plugin_notification::NotificationExt;
use tracing::{info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertContent {
    pub title: String,
    pub body: String,
    pub risk_level: String,
    pub risk_score: i32,
    pub severity: String,
    pub actions: Vec<String>,
}

pub struct NotificationManager {
    recent_alerts: Mutex<HashSet<String>>,
}

impl Default for NotificationManager {
    fn default() -> Self {
        Self::new()
    }
}

impl NotificationManager {
    pub fn new() -> Self {
        NotificationManager {
            recent_alerts: Mutex::new(HashSet::new()),
        }
    }

    pub fn send_alert(&self, app: &AppHandle, content: &AlertContent) {
        let dedup_key = format!("{}|{}", content.title, content.risk_level);

        {
            let mut recent = self.recent_alerts.lock().unwrap();
            if recent.contains(&dedup_key) {
                debug!("Suppressing duplicate alert: {}", dedup_key);
                return;
            }
            recent.insert(dedup_key.clone());
            if recent.len() > 50 {
                recent.clear();
            }
        }

        info!(
            "Alert [{}] {} — score={}",
            content.severity, content.title, content.risk_score
        );

        let body = if content.actions.is_empty() {
            content.body.clone()
        } else {
            format!("{}\n\nActions: {}", content.body, content.actions.join(" | "))
        };

        match app.notification().builder().title(&content.title).body(&body).show() {
            Ok(_) => debug!("Notification sent: {}", content.title),
            Err(e) => warn!("Failed to send notification: {}", e),
        }
    }

    pub fn safe(&self, app: &AppHandle, ssid: &str) {
        self.send_alert(
            app,
            &AlertContent {
                title: "WiFi Connection Safe".to_string(),
                body: format!(
                    "Connected to \"{}\" — no threats detected. Network appears legitimate.",
                    ssid
                ),
                risk_level: "Safe".to_string(),
                risk_score: 0,
                severity: "info".to_string(),
                actions: vec!["View Details".to_string(), "Trust Network".to_string()],
            },
        );
    }

    pub fn suspicious(&self, app: &AppHandle, ssid: &str, reasons: &[String]) {
        let body = if reasons.is_empty() {
            format!(
                "Network \"{}\" triggered a suspicious detection. Review recommended.",
                ssid
            )
        } else {
            format!(
                "Network \"{}\" shows suspicious behavior:\n• {}",
                ssid,
                reasons.join("\n• ")
            )
        };

        self.send_alert(
            app,
            &AlertContent {
                title: "Suspicious WiFi Network".to_string(),
                body,
                risk_level: "Suspicious".to_string(),
                risk_score: 35,
                severity: "warning".to_string(),
                actions: vec![
                    "View Details".to_string(),
                    "Ignore".to_string(),
                    "Trust Network".to_string(),
                ],
            },
        );
    }

    pub fn high_risk(&self, app: &AppHandle, ssid: &str, reasons: &[String]) {
        let body = format!(
            "HIGH RISK on \"{}\":\n• {}\n\nAvoid entering any credentials.",
            ssid,
            reasons.join("\n• ")
        );

        self.send_alert(
            app,
            &AlertContent {
                title: "⚠ High Risk WiFi Detected".to_string(),
                body,
                risk_level: "High Risk".to_string(),
                risk_score: 65,
                severity: "error".to_string(),
                actions: vec![
                    "View Details".to_string(),
                    "Ignore".to_string(),
                    "Trust Network".to_string(),
                ],
            },
        );
    }

    pub fn critical(&self, app: &AppHandle, ssid: &str, reasons: &[String]) {
        let body = format!(
            "🚨 CRITICAL — \"{}\" is likely a fake captive portal:\n• {}\n\nDo NOT enter any credentials. Disconnect immediately.",
            ssid,
            reasons.join("\n• ")
        );

        self.send_alert(
            app,
            &AlertContent {
                title: "🚨 Fake WiFi Portal Detected".to_string(),
                body,
                risk_level: "Critical".to_string(),
                risk_score: 90,
                severity: "critical".to_string(),
                actions: vec![
                    "View Details".to_string(),
                    "Ignore".to_string(),
                    "Trust Network".to_string(),
                ],
            },
        );
    }

    pub fn phishing_login(&self, app: &AppHandle, domain: &str, reasons: &[String]) {
        let body = format!(
            "The page at \"{}\" appears to be a phishing attempt:\n• {}\n\nDo not enter your credentials.",
            domain,
            reasons.join("\n• ")
        );

        self.send_alert(
            app,
            &AlertContent {
                title: "🚨 Phishing Login Page Detected".to_string(),
                body,
                risk_level: "Critical".to_string(),
                risk_score: 80,
                severity: "critical".to_string(),
                actions: vec!["View Details".to_string(), "Ignore".to_string()],
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alert_content_creation() {
        let content = AlertContent {
            title: "Test Alert".to_string(),
            body: "Test body".to_string(),
            risk_level: "Safe".to_string(),
            risk_score: 0,
            severity: "info".to_string(),
            actions: vec!["OK".to_string()],
        };
        assert_eq!(content.title, "Test Alert");
        assert_eq!(content.risk_score, 0);
    }

    #[test]
    fn test_alert_with_actions() {
        let content = AlertContent {
            title: "Alert".to_string(),
            body: "Body".to_string(),
            risk_level: "Critical".to_string(),
            risk_score: 80,
            severity: "critical".to_string(),
            actions: vec!["View".to_string(), "Ignore".to_string()],
        };
        assert_eq!(content.actions.len(), 2);
    }

    #[test]
    fn test_notification_manager_creation() {
        let manager = NotificationManager::new();
        let recent = manager.recent_alerts.lock().unwrap();
        assert!(recent.is_empty());
    }
}

