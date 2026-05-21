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
    pub has_hidden_inputs: bool,
    pub submit_text: Option<String>,
    pub suspicious_indicators: Vec<String>,
}

pub struct LoginPageAnalyzer {
    known_brands: Vec<&'static str>,
    suspicious_domains: Vec<&'static str>,
}

impl Default for LoginPageAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl LoginPageAnalyzer {
    pub fn new() -> Self {
        LoginPageAnalyzer {
            known_brands: vec![
                "google", "facebook", "apple", "microsoft", "outlook",
                "yahoo", "instagram", "twitter", "netflix", "paypal",
                "bank", "airbnb", "amazon", "dropbox", "adobe",
                "linkedin", "whatsapp", "telegram", "spotify", "steam",
                "ebay", "cloudflare", "wordpress", "godaddy", "shopify",
            ],
            suspicious_domains: vec![
                "secure", "account", "verify", "login", "service",
                "update", "confirm", "authentication", "validation",
            ],
        }
    }

    pub fn analyze(&self, html: &str, page_url: &str) -> LoginPageAnalysis {
        let mut indicators: Vec<String> = Vec::new();
        let lower = html.to_lowercase();

        let has_password_field = self.detect_password_field(&lower);

        let is_login_page = has_password_field
            || self.detect_login_form(&lower)
            || lower.contains("forgot password")
            || lower.contains("reset password")
            || lower.contains("recover password")
            || (lower.contains("sign in") && lower.contains("<form"))
            || (lower.contains("log in") && lower.contains("<form"));

        if !is_login_page {
            return LoginPageAnalysis {
                is_login_page: false,
                has_password_field: false,
                uses_https: page_url.starts_with("https://"),
                has_suspicious_branding: false,
                domain_consistent: true,
                form_action: None,
                has_hidden_inputs: false,
                submit_text: None,
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
            indicators.push("Form submits credentials to a different domain".to_string());
        }

        if has_password_field && !domain_consistent {
            indicators.push(
                "Password field sends data to external domain — credential harvesting risk"
                    .to_string(),
            );
        }

        let has_suspicious_branding = self.check_suspicious_branding(&lower, page_url);

        if has_suspicious_branding {
            indicators.push("Page uses known brand name but domain does not match".to_string());
        }

        let has_hidden_inputs = self.detect_hidden_inputs(&lower);
        if has_hidden_inputs {
            indicators.push("Form contains hidden input fields (common in phishing)".to_string());
        }

        let submit_text = self.extract_submit_text(&lower);
        if let Some(ref text) = submit_text {
            if self.is_suspicious_submit_text(text) {
                indicators.push(format!(
                    "Submit button text suggests urgency: \"{}\"",
                    text
                ));
            }
        }

        LoginPageAnalysis {
            is_login_page,
            has_password_field,
            uses_https,
            has_suspicious_branding,
            domain_consistent,
            form_action,
            has_hidden_inputs,
            submit_text,
            suspicious_indicators: indicators,
        }
    }

    fn detect_password_field(&self, lower: &str) -> bool {
        lower.contains("type=\"password\"")
            || lower.contains("type='password'")
            || lower.contains("type=password")
            || (lower.contains("password")
                && (lower.contains("<input") || lower.contains("<textarea")))
    }

    fn detect_login_form(&self, lower: &str) -> bool {
        let form_indicators = [
            "login", "sign in", "signin", "log in", "log-in",
        ];

        if let Some(form_start) = lower.find("<form") {
            let form_section = if let Some(end) = lower[form_start..].find("</form>") {
                &lower[form_start..=form_start + end]
            } else {
                &lower[form_start..]
            };

            for indicator in &form_indicators {
                if form_section.contains(indicator) {
                    return true;
                }
            }
        }

        false
    }

    fn extract_form_action(html: &str) -> Option<String> {
        let lower = html.to_lowercase();

        if let Some(form_start) = lower.find("<form") {
            let form_section = &lower[form_start..];
            if let Some(end) = form_section.find('>') {
                let form_tag = &form_section[..=end];

                for quote in ["\"", "'"] {
                    let pattern = format!("action={}", quote);
                    if let Some(action_start) = form_tag.find(&pattern) {
                        let after = &form_tag[action_start + pattern.len()..];
                        if let Some(quote_end) = after.find(quote) {
                            return Some(after[..quote_end].to_string());
                        }
                    }
                }

                if let Some(action_start) = form_tag.find("action=") {
                    let after = &form_tag[action_start + 7..];
                    let after = after.trim_start();
                    if !after.starts_with('"') && !after.starts_with('\'') {
                        if let Some(end) = after.find(&[' ', '>', '\t'][..]) {
                            return Some(after[..end].to_string());
                        }
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

    fn check_suspicious_branding(&self, lower_html: &str, page_url: &str) -> bool {
        let page_host = url::Url::parse(page_url)
            .ok()
            .and_then(|u| u.host_str().map(|s| s.to_lowercase()))
            .unwrap_or_default();

        for brand in &self.known_brands {
            if lower_html.contains(brand) {
                if !page_host.contains(brand) {
                    debug!("Suspicious branding: '{}' on {}", brand, page_host);
                    return true;
                }
            }
        }

        false
    }

    fn detect_hidden_inputs(&self, lower: &str) -> bool {
        let mut count = 0;
        let mut search_from = 0;

        while let Some(start) = lower[search_from..].find("<input") {
            let section = &lower[search_from + start..];
            let end = section.find('>').unwrap_or(section.len());
            let input_tag = &section[..=end];

            if input_tag.contains("type=\"hidden\"")
                || input_tag.contains("type='hidden'")
                || input_tag.contains("hidden")
            {
                count += 1;
            }

            search_from += start + end;
        }

        count > 2
    }

    fn extract_submit_text(&self, lower: &str) -> Option<String> {
        let patterns = [
            ("type=\"submit\"", "value=\""),
            ("type='submit'", "value='"),
            ("<button", ">"),
        ];

        for (tag_pattern, value_pattern) in &patterns {
            if let Some(pos) = lower.find(tag_pattern) {
                let before = &lower[..pos];
                if let Some(open_pos) = before.rfind('<') {
                    let tag = &lower[open_pos..pos + tag_pattern.len()];
                    if let Some(val_start) = tag.find(value_pattern) {
                        let after = &tag[val_start + value_pattern.len()..];
                        if let Some(end) = after.find(&['"', '\'', '>', '<'][..]) {
                            let text = after[..end].to_string();
                            if !text.is_empty() {
                                return Some(text);
                            }
                        }
                    }
                }
            }
        }

        None
    }

    fn is_suspicious_submit_text(&self, text: &str) -> bool {
        let lower = text.to_lowercase();
        let urgent = [
            "verify now", "confirm", "update account", "secure",
            "log in to secure", "validate", "unlock", "restore",
            "click here", "continue to", "accept",
        ];
        urgent.iter().any(|u| lower.contains(u))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_field_detected() {
        let a = LoginPageAnalyzer::new();
        let r = a.analyze(
            "<html><form action='/login'><input type='password'></form></html>",
            "https://example.com/login",
        );
        assert!(r.is_login_page);
        assert!(r.has_password_field);
    }

    #[test]
    fn test_no_login_normal_page() {
        let a = LoginPageAnalyzer::new();
        let r = a.analyze(
            "<html><h1>Welcome</h1><p>Content</p></html>",
            "https://example.com",
        );
        assert!(!r.is_login_page);
    }

    #[test]
    fn test_suspicious_branding() {
        let a = LoginPageAnalyzer::new();
        let r = a.analyze(
            r#"<html><form><input type="password">Google sign in</form></html>"#,
            "http://192.168.1.1/login",
        );
        assert!(r.has_suspicious_branding);
    }

    #[test]
    fn test_hidden_inputs_detected() {
        let a = LoginPageAnalyzer::new();
        let r = a.analyze(
            r#"<form>
                <input type="hidden" name="token" value="abc">
                <input type="hidden" name="return" value="xyz">
                <input type="hidden" name="id" value="123">
                <input type="password" name="pass">
               </form>"#,
            "https://example.com",
        );
        assert!(r.has_hidden_inputs);
    }

    #[test]
    fn test_no_hidden_inputs() {
        let a = LoginPageAnalyzer::new();
        let r = a.analyze(
            r#"<form><input type="password" name="pass"></form>"#,
            "https://example.com",
        );
        assert!(!r.has_hidden_inputs);
    }

    #[test]
    fn test_extract_form_action() {
        let html = r#"<form action="https://evil.com/login">"#;
        assert_eq!(
            LoginPageAnalyzer::extract_form_action(html),
            Some("https://evil.com/login".to_string())
        );
    }

    #[test]
    fn test_domain_mismatch() {
        let r = LoginPageAnalyzer::check_domain_consistency(
            "https://good.com",
            "https://evil.com/login",
        );
        assert!(!r);
    }

    #[test]
    fn test_domain_match() {
        let r = LoginPageAnalyzer::check_domain_consistency(
            "https://example.com",
            "https://example.com/login",
        );
        assert!(r);
    }

    #[test]
    fn test_submit_text_urgent() {
        let a = LoginPageAnalyzer::new();
        assert!(a.is_suspicious_submit_text("Verify Now"));
        assert!(a.is_suspicious_submit_text("Confirm Account"));
        assert!(!a.is_suspicious_submit_text("Sign In"));
    }
}
