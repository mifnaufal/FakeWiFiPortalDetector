use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::debug;
use url::Url;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedirectAnalysis {
    pub redirect_count: u32,
    pub suspicious: bool,
    pub final_url: String,
    pub initial_url: String,
    pub chain: Vec<String>,
    pub reasons: Vec<String>,
}

pub struct RedirectAnalyzer {
    client: Client,
    max_depth: u32,
    suspicious_tlds: Vec<String>,
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
            .expect("Failed to build HTTP client");

        RedirectAnalyzer {
            client,
            max_depth: 10,
            suspicious_tlds: vec![
                "tk".to_string(),
                "ml".to_string(),
                "ga".to_string(),
                "cf".to_string(),
                "gq".to_string(),
            ],
            suspicious_keywords: vec![
                "login".to_string(),
                "signin".to_string(),
                "verify".to_string(),
                "account".to_string(),
                "update".to_string(),
                "secure".to_string(),
                "confirm".to_string(),
            ],
        }
    }

    pub fn analyze(&self, url: &str) -> RedirectAnalysis {
        let mut chain = Vec::new();
        let mut reasons = Vec::new();
        let mut current_url = url.to_string();
        let mut redirect_count = 0;

        chain.push(current_url.clone());

        loop {
            if redirect_count >= self.max_depth {
                reasons.push("Redirect loop or max depth exceeded".to_string());
                break;
            }

            let response = match self
                .client
                .get(&current_url)
                .send()
            {
                Ok(resp) => resp,
                Err(e) => {
                    reasons.push(format!("Request error: {}", e));
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
                    redirect_count += 1;
                    let resolved = Self::resolve_url(&current_url, &next_url);
                    chain.push(resolved.clone());
                    current_url = resolved;
                }
                None => break,
            }
        }

        if redirect_count > 0 {
            if self.is_suspicious_domain(&current_url) {
                reasons.push("Final domain appears suspicious".to_string());
            }

            if self.is_ip_redirect(&chain) {
                reasons.push("Redirect points to raw IP address".to_string());
            }

            if self.domain_switched(&chain) {
                reasons.push("Redirect switched to different domain".to_string());
            }

            if self.contains_suspicious_path(&current_url) {
                reasons.push("Redirect URL contains suspicious keywords".to_string());
            }
        }

        let suspicious = !reasons.is_empty();

        RedirectAnalysis {
            redirect_count,
            suspicious,
            final_url: current_url,
            initial_url: url.to_string(),
            chain,
            reasons,
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
                        return true;
                    }
                }
            }
        }
        false
    }

    fn is_ip_redirect(&self, chain: &[String]) -> bool {
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

        let first_domain = Url::parse(&chain[0])
            .ok()
            .and_then(|u| u.host_str().map(|s| s.to_string()));

        let last_domain = Url::parse(&chain[chain.len() - 1])
            .ok()
            .and_then(|u| u.host_str().map(|s| s.to_string()));

        match (first_domain, last_domain) {
            (Some(first), Some(last)) => first != last,
            _ => false,
        }
    }

    fn contains_suspicious_path(&self, url: &str) -> bool {
        let lower = url.to_lowercase();
        self.suspicious_keywords
            .iter()
            .any(|kw| lower.contains(kw))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_suspicious_tld() {
        let analyzer = RedirectAnalyzer::new();
        assert!(analyzer.is_suspicious_domain("http://login.tk"));
        assert!(!analyzer.is_suspicious_domain("http://example.com"));
    }

    #[test]
    fn test_ip_detection() {
        let analyzer = RedirectAnalyzer::new();
        let chain = vec![
            "http://example.com".to_string(),
            "http://192.168.1.1/login".to_string(),
        ];
        assert!(analyzer.is_ip_redirect(&chain));
    }

    #[test]
    fn test_domain_switch() {
        let analyzer = RedirectAnalyzer::new();
        let chain = vec![
            "http://example.com".to_string(),
            "http://evil.com".to_string(),
        ];
        assert!(analyzer.domain_switched(&chain));
    }
}
