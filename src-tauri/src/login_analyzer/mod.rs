use serde::{Deserialize, Serialize};
use tracing::debug;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginPageAnalysis {
    pub is_login_page: bool,
    pub has_password_field: bool,
    pub uses_https: bool,
    pub has_suspicious_branding: bool,
    pub domain_consistent: bool,
    pub form_action: Option<String>,
    pub suspicious_indicators: Vec<String>,
}

pub struct LoginPageAnalyzer;

impl LoginPageAnalyzer {
    pub fn new() -> Self {
        LoginPageAnalyzer
    }

    pub fn analyze(&self, html: &str, page_url: &str) -> LoginPageAnalysis {
        let mut indicators: Vec<String> = Vec::new();
        let lower = html.to_lowercase();

        let has_password_field = lower.contains("type=\"password\"")
            || lower.contains("type='password'")
            || lower.contains("password")
                && (lower.contains("<input") || lower.contains("<textarea"));

        let is_login_page = has_password_field
            || lower.contains("<form")
                && (lower.contains("login")
                    || lower.contains("sign in")
                    || lower.contains("signin")
                    || lower.contains("log in"))
            || lower.contains("forgot password")
            || lower.contains("reset password");

        if !is_login_page {
            return LoginPageAnalysis {
                is_login_page: false,
                has_password_field: false,
                uses_https: page_url.starts_with("https://"),
                has_suspicious_branding: false,
                domain_consistent: true,
                form_action: None,
                suspicious_indicators: vec![],
            };
        }

        let uses_https = page_url.starts_with("https://");

        if !uses_https {
            indicators.push("Login page is not served over HTTPS".to_string());
        }

        let form_action = Self::extract_form_action(html);
        let domain_consistent = if let Some(ref action) = form_action {
            Self::check_domain_consistency(page_url, action)
        } else {
            true
        };

        if !domain_consistent {
            indicators.push("Form submits to a different domain".to_string());
        }

        let has_suspicious_branding = Self::check_suspicious_branding(html, page_url);

        if has_suspicious_branding {
            indicators.push("Suspicious or mismatched branding detected".to_string());
        }

        if has_password_field && !domain_consistent {
            indicators.push("Password field submits credentials to external domain".to_string());
        }

        LoginPageAnalysis {
            is_login_page,
            has_password_field,
            uses_https,
            has_suspicious_branding,
            domain_consistent,
            form_action,
            suspicious_indicators: indicators,
        }
    }

    fn extract_form_action(html: &str) -> Option<String> {
        let lower = html.to_lowercase();

        if let Some(form_start) = lower.find("<form") {
            let form_section = &lower[form_start..];
            if let Some(end) = form_section.find('>') {
                let form_tag = &form_section[..=end];
                if let Some(action_start) = form_tag.find("action=\"") {
                    let after = &form_tag[action_start + 8..];
                    if let Some(quote_end) = after.find('"') {
                        return Some(after[..quote_end].to_string());
                    }
                }
                if let Some(action_start) = form_tag.find("action='") {
                    let after = &form_tag[action_start + 8..];
                    if let Some(quote_end) = after.find('\'') {
                        return Some(after[..quote_end].to_string());
                    }
                }
            }
        }
        None
    }

    fn check_domain_consistency(page_url: &str, form_action: &str) -> bool {
        if form_action.starts_with("http://") || form_action.starts_with("https://") {
            if let Ok(page_parsed) = url::Url::parse(page_url) {
                if let Ok(action_parsed) = url::Url::parse(form_action) {
                    return page_parsed.host_str() == action_parsed.host_str();
                }
            }
        }
        true
    }

    fn check_suspicious_branding(html: &str, page_url: &str) -> bool {
        let known_brands = [
            "google",
            "facebook",
            "apple",
            "microsoft",
            "outlook",
            "yahoo",
            "instagram",
            "twitter",
            "netflix",
            "paypal",
            "bank",
            "airbnb",
            "amazon",
        ];

        let lower_html = html.to_lowercase();
        let page_host = url::Url::parse(page_url)
            .ok()
            .and_then(|u| u.host_str().map(|s| s.to_lowercase()))
            .unwrap_or_default();

        for brand in &known_brands {
            if lower_html.contains(brand) {
                if !page_host.contains(brand) {
                    return true;
                }
            }
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_field_detected() {
        let analyzer = LoginPageAnalyzer::new();
        let result = analyzer.analyze(
            "<html><form action='/login'><input type='password'></form></html>",
            "https://example.com/login",
        );
        assert!(result.is_login_page);
        assert!(result.has_password_field);
    }

    #[test]
    fn test_no_login_normal_page() {
        let analyzer = LoginPageAnalyzer::new();
        let result = analyzer.analyze(
            "<html><h1>Welcome</h1><p>Some content</p></html>",
            "https://example.com",
        );
        assert!(!result.is_login_page);
    }

    #[test]
    fn test_suspicious_branding() {
        let analyzer = LoginPageAnalyzer::new();
        let result = analyzer.analyze(
            r#"<html><form><input type="password">Google sign in</form></html>"#,
            "http://192.168.1.1/login",
        );
        assert!(result.has_suspicious_branding);
    }
}
