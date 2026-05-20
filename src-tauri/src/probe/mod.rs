use reqwest::blocking::Client;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::{debug, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeResult {
    pub captive_portal_detected: bool,
    pub probe_target: String,
    pub status_code: u16,
    pub content_type: String,
    pub body_preview: String,
    pub redirect_url: Option<String>,
}

pub struct ProbeEngine {
    client: Client,
    targets: Vec<String>,
    timeout: Duration,
}

impl Default for ProbeEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl ProbeEngine {
    pub fn new() -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::limited(10))
            .use_rustls_tls()
            .build()
            .expect("Failed to build HTTP client");

        let targets = vec![
            "https://captive.g.apple.com/hotspot-detect.html".to_string(),
            "https://nmcheck.gnome.org/check_network_status.txt".to_string(),
            "http://connectivitycheck.platform.hmms.gov.cn/generate_204".to_string(),
        ];

        ProbeEngine {
            client,
            targets,
            timeout: Duration::from_secs(5),
        }
    }

    pub fn with_targets(mut self, targets: Vec<String>) -> Self {
        self.targets = targets;
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn probe_all(&self) -> Vec<ProbeResult> {
        let mut results = Vec::new();

        for target in &self.targets {
            debug!("Probing: {}", target);
            let result = self.probe_single(target);
            results.push(result);
        }

        results
    }

    fn probe_single(&self, url: &str) -> ProbeResult {
        let default_result = ProbeResult {
            captive_portal_detected: false,
            probe_target: url.to_string(),
            status_code: 0,
            content_type: String::new(),
            body_preview: String::new(),
            redirect_url: None,
        };

        let response = match self.client.get(url).send() {
            Ok(resp) => resp,
            Err(e) => {
                warn!("Probe failed for {}: {}", url, e);
                return default_result;
            }
        };

        let status_code = response.status().as_u16();
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let redirect_url = response.url().to_string();
        let is_redirected = redirect_url != url;

        let body_preview = response
            .text()
            .unwrap_or_default()
            .chars()
            .take(200)
            .collect::<String>();

        let captive_portal_detected = Self::is_portal_response(
            status_code,
            &content_type,
            &body_preview,
            is_redirected,
        );

        ProbeResult {
            captive_portal_detected,
            probe_target: url.to_string(),
            status_code,
            content_type,
            body_preview,
            redirect_url: if is_redirected { Some(redirect_url) } else { None },
        }
    }

    fn is_portal_response(
        status_code: u16,
        content_type: &str,
        body: &str,
        is_redirected: bool,
    ) -> bool {
        if is_redirected {
            return true;
        }

        if status_code == StatusCode::OK.as_u16() {
            if content_type.contains("text/html") {
                let lower = body.to_lowercase();
                if lower.contains("<form")
                    || lower.contains("password")
                    || lower.contains("sign in")
                    || lower.contains("login")
                    || lower.contains("wifi")
                    || lower.contains("captive")
                {
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
    fn test_portal_detection_redirect() {
        assert!(ProbeEngine::is_portal_response(302, "text/html", "", true));
    }

    #[test]
    fn test_portal_detection_login_form() {
        assert!(ProbeEngine::is_portal_response(
            200,
            "text/html",
            "<html><form><input type='password'></form></html>",
            false
        ));
    }

    #[test]
    fn test_normal_response_not_portal() {
        assert!(!ProbeEngine::is_portal_response(
            204,
            "",
            "",
            false
        ));
    }
}
