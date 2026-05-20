use rustls::pki_types::{CertificateDer, ServerName};
use rustls::ClientConfig;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::sync::Arc;
use std::time::Duration;
use tracing::warn;
use x509_parser::prelude::*;
use x509_parser::time::ASN1Time;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsResult {
    pub valid: bool,
    pub expired: bool,
    pub self_signed: bool,
    pub hostname_match: bool,
    pub issuer: Option<String>,
    pub subject: Option<String>,
    pub error_message: Option<String>,
}

pub struct TlsValidator {
    config: Arc<ClientConfig>,
}

impl Default for TlsValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl TlsValidator {
    pub fn new() -> Self {
        let config = ClientConfig::builder()
            .with_root_certificates(Self::load_roots())
            .with_no_client_auth();

        TlsValidator {
            config: Arc::new(config),
        }
    }

    fn load_roots() -> rustls::RootCertStore {
        let mut roots = rustls::RootCertStore::empty();
        for cert in webpki_roots::TLS_SERVER_ROOTS.iter() {
            let _ = roots.add(cert.clone());
        }
        roots
    }

    pub fn validate(&self, hostname: &str, port: u16) -> TlsResult {
        let addr = format!("{}:{}", hostname, port);

        let server_name = match ServerName::try_from(hostname) {
            Ok(name) => name,
            Err(e) => {
                return error_result(&format!("Invalid hostname: {}", e));
            }
        };

        let mut config = (*self.config).clone();
        let mut client = match rustls::ClientConnection::new(Arc::new(config), server_name) {
            Ok(c) => c,
            Err(e) => {
                return error_result(&format!("TLS init: {}", e));
            }
        };

        let mut socket = match std::net::TcpStream::connect(&addr) {
            Ok(s) => s,
            Err(e) => {
                return error_result(&format!("TCP connect: {}", e));
            }
        };

        socket.set_read_timeout(Some(Duration::from_secs(5))).ok();
        socket.set_write_timeout(Some(Duration::from_secs(5))).ok();

        let mut tls = rustls::Stream::new(&mut client, &mut socket);

        let request = format!(
            "GET / HTTP/1.0\r\nHost: {}\r\nConnection: close\r\n\r\n",
            hostname
        );

        if let Err(e) = tls.write_all(request.as_bytes()) {
            warn!("TLS write error {}: {}", hostname, e);
            return error_result(&format!("TLS write: {}", e));
        }

        let mut response = Vec::new();
        if let Err(e) = tls.read_to_end(&mut response) {
            if !e.to_string().contains("eof") {
                warn!("TLS read error {}: {}", hostname, e);
            }
        }

        let (_, mut client) = tls.into_ref();
        let peer_certs: Vec<CertificateDer> = client
            .peer_certificates()
            .map(|c| c.to_vec())
            .unwrap_or_default();

        if peer_certs.is_empty() {
            return error_result("No peer certificates");
        }

        let leaf = &peer_certs[0];
        let parsed = match parse_x509_certificate(leaf) {
            Ok((_, cert)) => cert,
            Err(e) => {
                return error_result(&format!("Cert parse: {}", e));
            }
        };

        let now_ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let now_asn1 = ASN1Time::from_timestamp(now_ts);
        let expired = now_asn1 > parsed.validity().not_after;

        let self_signed = peer_certs.len() == 1;

        let subject = parsed.subject().to_string();
        let issuer = parsed.issuer().to_string();

        let hostname_lower = hostname.to_lowercase();
        let hostname_match = subject.to_lowercase().contains(&hostname_lower)
            || parsed
                .subject_alternative_names()
                .iter()
                .flatten()
                .any(|san| san.to_lowercase().contains(&hostname_lower));

        let valid = !expired && hostname_match;

        TlsResult {
            valid,
            expired,
            self_signed,
            hostname_match,
            issuer: Some(issuer),
            subject: Some(subject),
            error_message: if !valid {
                Some(format!(
                    "expired={} hostname_mismatch={} self_signed={}",
                    expired, !hostname_match, self_signed
                ))
            } else {
                None
            },
        }
    }
}

fn error_result(msg: &str) -> TlsResult {
    TlsResult {
        valid: false,
        expired: false,
        self_signed: false,
        hostname_match: false,
        issuer: None,
        subject: None,
        error_message: Some(msg.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_validator_creation() {
        let validator = TlsValidator::new();
        let result = validator.validate("example.com", 443);
        assert!(!result.valid);
    }
}
