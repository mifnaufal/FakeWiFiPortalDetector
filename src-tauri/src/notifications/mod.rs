use serde::{Deserialize, Serialize};
use tauri::AppHandle;
use tauri_plugin_notification::NotificationExt;
use tracing::info;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertContent {
    pub title: String,
    pub body: String,
    pub risk_level: String,
    pub risk_score: i32,
    pub actions: Vec<String>,
}

pub struct NotificationManager;

impl NotificationManager {
    pub fn new() -> Self {
        NotificationManager
    }

    pub fn send_alert(app: &AppHandle, content: &AlertContent) {
        info!(
            "Sending notification: {} - {}",
            content.title, content.risk_level
        );

        let body = if content.actions.is_empty() {
            content.body.clone()
        } else {
            format!("{}\n\nActions: {}", content.body, content.actions.join(" | "))
        };

        let _ = app.notification()
            .builder()
            .title(&content.title)
            .body(&body)
            .show();
    }

    pub fn safe_notification(app: &AppHandle, ssid: &str) {
        let content = AlertContent {
            title: "WiFi Connection Safe".to_string(),
            body: format!("Connected to \"{}\" — no threats detected.", ssid),
            risk_level: "Safe".to_string(),
            risk_score: 0,
            actions: vec!["View Details".to_string(), "Trust Network".to_string()],
        };
        Self::send_alert(app, &content);
    }

    pub fn suspicious_notification(app: &AppHandle, ssid: &str, reasons: &[String]) {
        let reason_text = reasons.join("\n");
        let content = AlertContent {
            title: "Suspicious WiFi Network Detected".to_string(),
            body: format!(
                "Network \"{}\" shows suspicious behavior:\n{}",
                ssid, reason_text
            ),
            risk_level: "Suspicious".to_string(),
            risk_score: 30,
            actions: vec![
                "View Details".to_string(),
                "Ignore".to_string(),
                "Trust Network".to_string(),
            ],
        };
        Self::send_alert(app, &content);
    }

    pub fn critical_notification(app: &AppHandle, ssid: &str, reasons: &[String]) {
        let reason_text = reasons.join("\n");
        let content = AlertContent {
            title: "Critical — Fake WiFi Portal Detected".to_string(),
            body: format!(
                "DANGER: \"{}\" may be attempting credential phishing:\n{}",
                ssid, reason_text
            ),
            risk_level: "Critical".to_string(),
            risk_score: 80,
            actions: vec![
                "View Details".to_string(),
                "Ignore".to_string(),
                "Trust Network".to_string(),
            ],
        };
        Self::send_alert(app, &content);
    }

    pub fn phishing_login_warning(app: &AppHandle, domain: &str) {
        let content = AlertContent {
            title: "Suspicious Login Page Detected".to_string(),
            body: format!(
                "The page at {} appears to be a phishing attempt. \
                 Do not enter your credentials.",
                domain
            ),
            risk_level: "Critical".to_string(),
            risk_score: 70,
            actions: vec![
                "View Details".to_string(),
                "Ignore".to_string(),
            ],
        };
        Self::send_alert(app, &content);
    }
}
