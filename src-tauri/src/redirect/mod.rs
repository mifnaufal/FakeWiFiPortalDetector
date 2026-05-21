use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::time::Duration;
use tracing::{debug, warn};
use url::Url;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedirectAnalysis {
    pub redirect_count: u32,
    pub suspicious: bool,
    pub final_url: String,
    pub initial_url: String,
    pub chain: Vec<String>,
    pub reasons: Vec<String>,
    pub http_downgrade: bool,
}

pub struct RedirectAnalyzer {
    client: Client,
    max_depth: u32,
    suspicious_tlds: HashSet<String>,
    suspicious_keywords: Vec<String>,
}

impl Default for RedirectAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl RedirectAnalyzer {
    pub fn new() -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .use_rustls_tls()
            .build()
            .expect("Failed to build redirect client");

        RedirectAnalyzer {
            client,
            max_depth: 10,
            suspicious_tlds: [
                "tk", "ml", "ga", "cf", "gq", "xyz", "top", "club",
                "work", "date", "men", "loan", "win", "bid", "trade",
                "webcam", "science", "download", "ringtone", "country",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            suspicious_keywords: vec![
                "login", "signin", "verify", "account", "update",
                "secure", "confirm", "authenticate", "validate",
                "unlock", "restore", "recover", "wallet", "billing",
            ],
        }
    }

    pub fn analyze(&self, url: &str) -> RedirectAnalysis {
        let mut chain = Vec::new();
        let mut reasons = Vec::new();
        let mut visited = HashSet::new();
        let mut current_url = url.to_string();
        let mut redirect_count = 0;
        let mut http_downgrade = false;

        chain.push(current_url.clone());
        visited.insert(current_url.clone());

        loop {
            if redirect_count >= self.max_depth {
                reasons.push("Redirect max depth exceeded".to_string());
                break;
            }

            let response = match self.client.get(&current_url).send() {
                Ok(resp) => resp,
                Err(e) => {
                    if redirect_count > 0 {
                        reasons.push(format!("Request failed: {}", e));
                    }
                    break;
                }
            };

            let status = response.status().as_u16();

            if !(300..=399).contains(&status) {
                break;
            }

            let location = response
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());

            match location {
                Some(next_url) => {
                    let resolved = Self::resolve_url(&current_url, &next_url);

                    let scheme = Url::parse(&resolved)
                        .ok()
                        .map(|u| u.scheme().to_string())
                        .unwrap_or_default();

                    if !scheme.starts_with("http") {
                        reasons.push(format!(
                            "Redirect uses non-HTTP scheme: {}",
                            scheme
                        ));
                        break;
                    }

                    if visited.contains(&resolved) {
                        reasons.push("Redirect loop detected".to_string());
                        break;
                    }

                    redirect_count += 1;
                    visited.insert(resolved.clone());
                    chain.push(resolved.clone());
                    current_url = resolved;
                }
                None => break,
            }
        }

        if redirect_count > 0 {
            // HTTP → HTTPS downgrade
            if let (Ok(initial), Ok(final_url)) =
                (Url::parse(&chain[0]), Url::parse(&current_url))
            {
                if initial.scheme() == "https" && final_url.scheme() == "http" {
                    http_downgrade = true;
                    reasons.push("HTTPS to HTTP downgrade detected".to_string());
                }
            }

            if self.is_suspicious_domain(&current_url) {
                reasons.push("Final domain uses suspicious TLD".to_string());
            }

            if self.is_ip_address_in_chain(&chain) {
                reasons.push("Redirect chain contains raw IP address".to_string());
            }

            if self.domain_switched(&chain) {
                reasons.push("Redirect switched to a different domain".to_string());
            }

            if self.contains_suspicious_path(&current_url) {
                reasons.push("Redirect URL contains phishing keywords".to_string());
            }

            let domains: HashSet<&str> = chain
                .iter()
                .filter_map(|u| Url::parse(u).ok())
                .filter_map(|u| u.host_str().map(|h| h.to_lowercase()))
                .collect();

            if domains.len() > 1 {
                reasons.push("Multiple domain hops in redirect chain".to_string());
            }
        }

        let suspicious = !reasons.is_empty();

        if suspicious {
            warn!(
                "Suspicious redirect: {} → {} ({} reasons)",
                url,
                current_url,
                reasons.len()
            );
        }

        RedirectAnalysis {
            redirect_count,
            suspicious,
            final_url: current_url,
            initial_url: url.to_string(),
            chain,
            reasons,
            http_downgrade,
        }
    }

    fn resolve_url(base: &str, next: &str) -> String {
        if next.starts_with("http://") || next.starts_with("https://") {
            return next.to_string();
        }

        if let Ok(base_url) = Url::parse(base) {
            if let Ok(resolved) = base_url.join(next) {
                return resolved.to_string();
            }
        }

        next.to_string()
    }

    fn is_suspicious_domain(&self, url: &str) -> bool {
        if let Ok(parsed) = Url::parse(url) {
            if let Some(host) = parsed.host_str() {
                if let Some(tld) = host.rsplit('.').next() {
                    if self.suspicious_tlds.contains(&tld.to_lowercase()) {
                        debug!("Suspicious TLD detected: .{}", tld);
                        return true;
                    }
                }
            }
        }
        false
    }

    fn is_ip_address_in_chain(&self, chain: &[String]) -> bool {
        for url_str in chain {
            if let Ok(parsed) = Url::parse(url_str) {
                if let Some(host) = parsed.host_str() {
                    if host.parse::<std::net::IpAddr>().is_ok() {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn domain_switched(&self, chain: &[String]) -> bool {
        if chain.len() < 2 {
            return false;
        }

        let first = Url::parse(&chain[0])
            .ok()
            .and_then(|u| u.host_str().map(|s| s.to_lowercase()));

        let last = Url::parse(&chain[chain.len() - 1])
            .ok()
            .and_then(|u| u.host_str().map(|s| s.to_lowercase()));

        match (first, last) {
            (Some(f), Some(l)) => f != l,
            _ => false,
        }
    }

    fn contains_suspicious_path(&self, url: &str) -> bool {
        let lower = url.to_lowercase();
        let path = Url::parse(url)
            .ok()
            .map(|u| u.path().to_lowercase())
            .unwrap_or_default();

        self.suspicious_keywords
            .iter()
            .any(|kw| lower.contains(kw) || path.contains(kw))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_suspicious_tld() {
        let a = RedirectAnalyzer::new();
        assert!(a.is_suspicious_domain("http://login.tk"));
        assert!(!a.is_suspicious_domain("http://example.com"));
    }

    #[test]
    fn test_ip_detection() {
        let a = RedirectAnalyzer::new();
        let chain = vec![
            "http://example.com".to_string(),
            "http://192.168.1.1/login".to_string(),
        ];
        assert!(a.is_ip_address_in_chain(&chain));
    }

    #[test]
    fn test_domain_switch() {
        let a = RedirectAnalyzer::new();
        let chain = vec![
            "http://example.com".to_string(),
            "http://evil.com".to_string(),
        ];
        assert!(a.domain_switched(&chain));
    }

    #[test]
    fn test_no_domain_switch() {
        let a = RedirectAnalyzer::new();
        let chain = vec![
            "http://example.com".to_string(),
            "http://example.com/login".to_string(),
        ];
        assert!(!a.domain_switched(&chain));
    }

    #[test]
    fn test_resolve_url_absolute() {
        assert_eq!(
            RedirectAnalyzer::resolve_url("http://a.com", "http://b.com"),
            "http://b.com"
        );
    }

    #[test]
    fn test_resolve_url_relative() {
        assert_eq!(
            RedirectAnalyzer::resolve_url("http://a.com/path", "/other"),
            "http://a.com/other"
        );
    }

    #[test]
    fn test_suspicious_keywords() {
        let a = RedirectAnalyzer::new();
        assert!(a.contains_suspicious_path("http://evil.com/login"));
        assert!(a.contains_suspicious_path("http://evil.com/verify"));
        assert!(!a.contains_suspicious_path("http://evil.com/home"));
    }
}
