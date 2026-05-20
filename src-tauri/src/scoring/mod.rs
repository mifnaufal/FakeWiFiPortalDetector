use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RiskLevel {
    Safe,
    Suspicious,
    HighRisk,
    Critical,
}

impl RiskLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            RiskLevel::Safe => "Safe",
            RiskLevel::Suspicious => "Suspicious",
            RiskLevel::HighRisk => "High Risk",
            RiskLevel::Critical => "Critical",
        }
    }

    pub fn from_score(score: i32) -> Self {
        match score {
            0..=20 => RiskLevel::Safe,
            21..=50 => RiskLevel::Suspicious,
            51..=80 => RiskLevel::HighRisk,
            _ => RiskLevel::Critical,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoringInput {
    pub invalid_ssl: bool,
    pub hostname_mismatch: bool,
    pub suspicious_redirect: bool,
    pub phishing_login_page: bool,
    pub is_trusted_network: bool,
    pub redirect_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoreResult {
    pub total_score: i32,
    pub risk_level: RiskLevel,
    pub breakdown: Vec<ScoreBreakdown>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoreBreakdown {
    pub factor: String,
    pub points: i32,
}

pub struct RiskEngine {
    weights: RiskWeights,
}

#[derive(Debug, Clone)]
pub struct RiskWeights {
    pub invalid_ssl: i32,
    pub hostname_mismatch: i32,
    pub suspicious_redirect: i32,
    pub phishing_login_page: i32,
    pub trusted_network_discount: i32,
    pub per_redirect_point: i32,
}

impl Default for RiskWeights {
    fn default() -> Self {
        RiskWeights {
            invalid_ssl: 40,
            hostname_mismatch: 35,
            suspicious_redirect: 25,
            phishing_login_page: 30,
            trusted_network_discount: -50,
            per_redirect_point: 2,
        }
    }
}

impl RiskEngine {
    pub fn new() -> Self {
        RiskEngine {
            weights: RiskWeights::default(),
        }
    }

    pub fn with_weights(weights: RiskWeights) -> Self {
        RiskEngine { weights }
    }

    pub fn evaluate(&self, input: &ScoringInput) -> ScoreResult {
        let mut score: i32 = 0;
        let mut breakdown = Vec::new();

        if input.invalid_ssl {
            score += self.weights.invalid_ssl;
            breakdown.push(ScoreBreakdown {
                factor: "Invalid SSL certificate".to_string(),
                points: self.weights.invalid_ssl,
            });
        }

        if input.hostname_mismatch {
            score += self.weights.hostname_mismatch;
            breakdown.push(ScoreBreakdown {
                factor: "SSL hostname mismatch".to_string(),
                points: self.weights.hostname_mismatch,
            });
        }

        if input.suspicious_redirect {
            score += self.weights.suspicious_redirect;
            breakdown.push(ScoreBreakdown {
                factor: "Suspicious redirect detected".to_string(),
                points: self.weights.suspicious_redirect,
            });
        }

        if input.phishing_login_page {
            score += self.weights.phishing_login_page;
            breakdown.push(ScoreBreakdown {
                factor: "Phishing login page detected".to_string(),
                points: self.weights.phishing_login_page,
            });
        }

        if input.redirect_count > 0 {
            let redirect_points = (input.redirect_count as i32) * self.weights.per_redirect_point;
            score += redirect_points;
            if redirect_points > 0 {
                breakdown.push(ScoreBreakdown {
                    factor: format!("{} redirect hops", input.redirect_count),
                    points: redirect_points,
                });
            }
        }

        if input.is_trusted_network {
            score += self.weights.trusted_network_discount;
            breakdown.push(ScoreBreakdown {
                factor: "Trusted network discount".to_string(),
                points: self.weights.trusted_network_discount,
            });
        }

        score = score.max(0);

        let risk_level = RiskLevel::from_score(score);

        ScoreResult {
            total_score: score,
            risk_level,
            breakdown,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_safe_network() {
        let engine = RiskEngine::new();
        let input = ScoringInput {
            invalid_ssl: false,
            hostname_mismatch: false,
            suspicious_redirect: false,
            phishing_login_page: false,
            is_trusted_network: false,
            redirect_count: 0,
        };
        let result = engine.evaluate(&input);
        assert_eq!(result.risk_level, RiskLevel::Safe);
        assert_eq!(result.total_score, 0);
    }

    #[test]
    fn test_critical_with_multiple_indicators() {
        let engine = RiskEngine::new();
        let input = ScoringInput {
            invalid_ssl: true,
            hostname_mismatch: true,
            suspicious_redirect: true,
            phishing_login_page: true,
            is_trusted_network: false,
            redirect_count: 5,
        };
        let result = engine.evaluate(&input);
        assert_eq!(result.risk_level, RiskLevel::Critical);
        assert!(result.total_score >= 100);
    }

    #[test]
    fn test_trusted_network_discount() {
        let engine = RiskEngine::new();
        let input = ScoringInput {
            invalid_ssl: true,
            hostname_mismatch: false,
            suspicious_redirect: false,
            phishing_login_page: false,
            is_trusted_network: true,
            redirect_count: 0,
        };
        let result = engine.evaluate(&input);
        assert_eq!(result.total_score, 0);
    }
}
