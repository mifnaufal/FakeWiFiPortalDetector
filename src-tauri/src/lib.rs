pub mod database;
pub mod logging;
pub mod login_analyzer;
pub mod network;
pub mod notifications;
pub mod probe;
pub mod redirect;
pub mod scoring;
pub mod tls;

use database::Database;
use network::{NetworkEvent, NetworkMonitor};
use probe::ProbeEngine;
use redirect::RedirectAnalyzer;
use scoring::{RiskEngine, ScoringInput};
use std::sync::Mutex;
use tauri::image::Image;
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager, State};

pub struct AppState {
    pub db: Mutex<Database>,
    pub network_monitor: Mutex<NetworkMonitor>,
    pub probe_engine: ProbeEngine,
    pub redirect_analyzer: RedirectAnalyzer,
    pub risk_engine: RiskEngine,
    pub tls_validator: tls::TlsValidator,
}

#[tauri::command]
fn get_scan_logs(state: State<AppState>) -> Result<Vec<database::ScanLog>, String> {
    let db = state.db.lock().map_err(|e| e.to_string())?;
    db.get_recent_logs(100).map_err(|e| e.to_string())
}

#[tauri::command]
fn get_trusted_networks(state: State<AppState>) -> Result<Vec<database::TrustedNetwork>, String> {
    let db = state.db.lock().map_err(|e| e.to_string())?;
    db.list_trusted_networks().map_err(|e| e.to_string())
}

#[tauri::command]
fn trust_network(ssid: String, state: State<AppState>) -> Result<(), String> {
    let db = state.db.lock().map_err(|e| e.to_string())?;
    db.add_trusted_network(&ssid, None)
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn remove_trusted_network(ssid: String, state: State<AppState>) -> Result<(), String> {
    let db = state.db.lock().map_err(|e| e.to_string())?;
    db.remove_trusted_network(&ssid)
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn is_trusted(ssid: String, state: State<AppState>) -> Result<bool, String> {
    let db = state.db.lock().map_err(|e| e.to_string())?;
    db.is_trusted_network(&ssid).map_err(|e| e.to_string())
}

#[tauri::command]
fn get_current_ssid() -> Result<Option<String>, String> {
    Ok(network::NetworkMonitor::get_ssid())
}

pub fn run() {
    logging::setup(None, "info");

    tauri::Builder::default()
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_shell::init())
        .setup(|app| {
            let db = Database::new(None).expect("Failed to initialize database");
            let monitor = NetworkMonitor::new();

            let state = AppState {
                db: Mutex::new(db),
                network_monitor: Mutex::new(monitor),
                probe_engine: ProbeEngine::new(),
                redirect_analyzer: RedirectAnalyzer::new(),
                risk_engine: RiskEngine::new(),
                tls_validator: tls::TlsValidator::new(),
            };

            let icon = Image::from_bytes(include_bytes!("../../assets/icon.png"))
                .expect("Failed to load tray icon");

            let _tray = TrayIconBuilder::new()
                .icon(icon)
                .tooltip("Fake WiFi Portal Detector")
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        if let Some(window) = tray.app_handle().get_webview_window("main") {
                            let _ = window.show();
                            let _ = window.set_focus();
                        }
                    }
                })
                .build(app)?;

            app.manage(state);

            let app_handle = app.handle().clone();

            let rx = {
                let monitor = app.state::<AppState>().network_monitor.lock().unwrap();
                monitor.get_receiver()
            };

            {
                let monitor = app.state::<AppState>().network_monitor.lock().unwrap();
                monitor.start();
            }

            std::thread::spawn(move || {
                while let Ok(event) = rx.recv() {
                    match event {
                        NetworkEvent::Connected(info) => {
                            let ssid = info.ssid.unwrap_or_default();
                            run_scan(&app_handle, &ssid);
                        }
                        NetworkEvent::Disconnected => {}
                        NetworkEvent::SsidChanged(_, new_ssid) => {
                            run_scan(&app_handle, &new_ssid);
                        }
                    }
                }
            });

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_scan_logs,
            get_trusted_networks,
            trust_network,
            remove_trusted_network,
            is_trusted,
            get_current_ssid,
        ])
        .run(tauri::generate_context!())
        .expect("Error running Tauri application");
}

fn run_scan(app: &AppHandle, ssid: &str) {
    use login_analyzer::LoginPageAnalyzer;
    use notifications::NotificationManager;
    use tracing::{error, info};

    let state: State<AppState> = app.state();

    info!("Running scan for SSID: {}", ssid);

    let is_trusted = state
        .db
        .lock()
        .ok()
        .and_then(|db| db.is_trusted_network(ssid).ok())
        .unwrap_or(false);

    let probe_results = state.probe_engine.probe_all();
    let captive_detected = probe_results.iter().any(|r| r.captive_portal_detected);

    let mut reasons: Vec<String> = Vec::new();
    let mut invalid_ssl = false;
    let mut hostname_mismatch = false;
    let mut suspicious_redirect = false;
    let mut phishing_login_page = false;
    let mut redirect_count: u32 = 0;

    let mut target_domain = String::new();

    if captive_detected {
        for result in &probe_results {
            if result.captive_portal_detected {
                let url = result
                    .redirect_url
                    .as_ref()
                    .map(|s| s.as_str())
                    .unwrap_or(&result.probe_target);

                if target_domain.is_empty() {
                    if let Some(domain) = extract_domain(url) {
                        target_domain = domain;
                    }
                }

                if let Some(ref redirect_url) = result.redirect_url {
                    let analysis = state.redirect_analyzer.analyze(redirect_url);
                    suspicious_redirect = analysis.suspicious;
                    redirect_count = analysis.redirect_count;

                    if analysis.suspicious {
                        reasons.extend(analysis.reasons.clone());
                    }
                }

                if !result.body_preview.is_empty() {
                    let la = LoginPageAnalyzer::new();
                    let login_result = la.analyze(&result.body_preview, url);
                    if login_result.is_login_page {
                        phishing_login_page = true;
                        reasons.extend(login_result.suspicious_indicators);
                    }
                }
            }
        }
    }

    if !target_domain.is_empty() {
        let tls_result = state.tls_validator.validate(&target_domain, 443);
        invalid_ssl = !tls_result.valid;
        hostname_mismatch = !tls_result.hostname_match;

        if invalid_ssl {
            reasons.push(format!(
                "Invalid SSL for {} (expired={})",
                target_domain, tls_result.expired
            ));
        }
        if hostname_mismatch {
            reasons.push(format!(
                "SSL hostname mismatch for {}",
                target_domain
            ));
        }
    }

    let scoring_input = ScoringInput {
        invalid_ssl,
        hostname_mismatch,
        suspicious_redirect,
        phishing_login_page,
        is_trusted_network: is_trusted,
        redirect_count,
    };

    let score_result = state.risk_engine.evaluate(&scoring_input);

    if let Err(e) = state.db.lock().map(|db| {
        db.insert_scan_log(
            ssid,
            &target_domain,
            score_result.total_score,
            score_result.risk_level.as_str(),
            &reasons.join("; "),
        )
    }) {
        error!("Failed to insert scan log: {}", e);
    }

    info!(
        "Scan complete for {} — score={}, level={}, reasons={}",
        ssid,
        score_result.total_score,
        score_result.risk_level.as_str(),
        reasons.len()
    );

    match score_result.risk_level {
        scoring::RiskLevel::Safe => {
            NotificationManager::safe_notification(app, ssid);
        }
        scoring::RiskLevel::Suspicious => {
            NotificationManager::suspicious_notification(app, ssid, &reasons);
        }
        scoring::RiskLevel::HighRisk | scoring::RiskLevel::Critical => {
            NotificationManager::critical_notification(app, ssid, &reasons);
        }
    }
}

fn extract_domain(url: &str) -> Option<String> {
    url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(|s| s.to_string()))
}
