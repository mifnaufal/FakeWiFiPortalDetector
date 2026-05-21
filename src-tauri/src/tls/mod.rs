use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::{debug, info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsResult {
    pub valid: bool,
    pub expired: bool,
    pub self_signed: bool,
    pub hostname_match: bool,
    pub error_message: Option<String>,
}

pub struct TlsValidator {
    client: Client,
}

impl Default for TlsValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl TlsValidator {
    pub fn new() -> Self {
        let client = Client::builder()
            .use_rustls_tls()
            .timeout(Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("Failed to build TLS client");

        TlsValidator { client }
    }

    pub fn validate(&self, hostname: &str, port: u16) -> TlsResult {
        let url = if port == 443 {
            format!("https://{}/", hostname)
        } else {
            format!("https://{}:{}/", hostname, port)
        };

        debug!("Validating TLS for {}", url);

        match self.client.get(&url).send() {
            Ok(resp) => {
                info!("TLS valid for {} (status={})", hostname, resp.status());
                TlsResult {
                    valid: true,
                    expired: false,
                    self_signed: false,
                    hostname_match: true,
                    error_message: None,
                }
            }
            Err(e) => {
                let err_str = e.to_string();
                let err_lower = err_str.to_lowercase();
                debug!("TLS check failed for {}: {}", hostname, err_str);

                let expired = err_lower.contains("expired")
                    || err_lower.contains("certificate has expired");
                let self_signed = err_lower.contains("self signed")
                    || err_lower.contains("self-signed");
                let hostname_mismatch = err_lower.contains("hostname mismatch")
                    || err_lower.contains("certnotvalidforname")
                    || err_lower.contains("certificate name mismatch");

                TlsResult {
                    valid: false,
                    expired,
                    self_signed,
                    hostname_match: !hostname_mismatch,
                    error_message: Some(err_str),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_validator_creation() {
        let validator = TlsValidator::new();
        let result = validator.validate("example.com", 443);
        assert!(!result.valid || result.expired);
    }

    #[test]
    fn test_tls_result_defaults() {
        let r = TlsResult {
            valid: false,
            expired: false,
            self_signed: false,
            hostname_match: false,
            error_message: None,
        };
        assert!(!r.valid);
        assert!(r.error_message.is_none());
    }

    #[test]
    fn test_tls_result_with_error() {
        let r = TlsResult {
            valid: false,
            expired: true,
            self_signed: false,
            hostname_match: false,
            error_message: Some("expired certificate".to_string()),
        };
        assert!(r.expired);
        assert_eq!(
            r.error_message.as_deref(),
            Some("expired certificate")
        );
    }

    #[test]
    fn test_tls_unknown_host() {
        let validator = TlsValidator::new();
        let result = validator.validate("invalid-host-that-does-not-exist-xyz.com", 443);
        assert!(!result.valid);
        assert!(result.error_message.is_some());
    }

    #[test]
    fn test_tls_bad_port() {
        let validator = TlsValidator::new();
        let result = validator.validate("example.com", 1);
        assert!(!result.valid);
    }
}
