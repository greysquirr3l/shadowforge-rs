//! HTTP adapter for canary tripwire notification.
//!
//! The canary shard is inert data: it carries a marker and nothing else,
//! and it cannot make a network request on its own. What it *can* do is
//! carry a URL. When a party who does not know what the canary is picks
//! it up, the tooling around it reaches that URL, and the fact that it
//! was reached is the alarm.
//!
//! This adapter is that tooling. It is an outbound HTTPS request and
//! nothing else — it never writes to disk and never reads a cover.

use std::time::Duration;

use crate::domain::errors::CanaryError;
use crate::domain::ports::CanaryNotifier;

/// How long to wait for the endpoint before giving up.
///
/// A canary check is something an operator runs while waiting for bad
/// news, so it must not hang. The default is short enough that a
/// `canary check` in a script does not stall the pipeline.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// Notifies a canary endpoint over HTTPS.
///
/// Only HTTPS is accepted. The request carries the fact that a
/// distribution was compromised, so it must not travel in clear text, and
/// a `file://` or `http://` URL would be a way to make the tool read
/// local files or hit internal services on the operator's network.
#[derive(Debug, Clone)]
pub struct HttpsCanaryNotifier {
    agent: ureq::Agent,
}

impl HttpsCanaryNotifier {
    /// Create a notifier with the default timeout.
    #[must_use]
    pub fn new() -> Self {
        Self::with_timeout(DEFAULT_TIMEOUT)
    }

    /// Create a notifier with an explicit timeout.
    #[must_use]
    pub fn with_timeout(timeout: Duration) -> Self {
        let config = ureq::Agent::config_builder()
            .timeout_global(Some(timeout))
            // A non-2xx response is a real answer from the endpoint, not a
            // transport failure. Turning off the automatic error lets the
            // status code be inspected, so `status` can say "not reached"
            // rather than failing on the way there.
            .http_status_as_error(false)
            .build();
        Self {
            agent: config.into(),
        }
    }
}

impl Default for HttpsCanaryNotifier {
    fn default() -> Self {
        Self::new()
    }
}

/// Reject anything that is not an HTTPS URL.
///
/// This is deliberately strict. A canary notification URL is chosen by
/// the operator when the distribution is set up, so there is no reason to
/// accept a scheme that cannot carry the alert safely.
fn validate_https_url(url: &str) -> Result<(), CanaryError> {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return Err(CanaryError::InvalidNotifyUrl {
            reason: "the URL is empty".into(),
        });
    }
    if !trimmed.starts_with("https://") {
        // Say which scheme was seen, so the operator can tell "http://"
        // from a typo like "https:/" or a stray "HTTPS://".
        let scheme = trimmed.split_once("://").map_or("(none)", |(s, _)| s);
        return Err(CanaryError::InvalidNotifyUrl {
            reason: format!("only https:// URLs are accepted, got scheme {scheme:?}"),
        });
    }
    // There has to be a host after the scheme.
    let host = trimmed
        .strip_prefix("https://")
        .unwrap_or_default()
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default();
    if host.is_empty() {
        return Err(CanaryError::InvalidNotifyUrl {
            reason: "the URL has no host".into(),
        });
    }
    Ok(())
}

impl CanaryNotifier for HttpsCanaryNotifier {
    fn notify(&self, url: &str) -> Result<(), CanaryError> {
        validate_https_url(url)?;

        // A GET rather than a HEAD: some endpoints only record a hit on a
        // full request, and the body of the response is not needed here.
        let response =
            self.agent
                .get(url.trim())
                .call()
                .map_err(|e| CanaryError::NotificationFailed {
                    reason: format!("could not reach {url}: {e}"),
                })?;

        // A non-2xx answer means the endpoint was reached but did not
        // accept the notification — usually a wrong URL. Reporting it as a
        // failure is the point: the operator must know the tripwire has
        // nowhere to fire.
        let status = response.status();
        if !status.is_success() {
            return Err(CanaryError::NotificationFailed {
                reason: format!("{url} answered HTTP {}", status.as_u16()),
            });
        }
        Ok(())
    }

    fn was_notified(&self, url: &str) -> Result<bool, CanaryError> {
        validate_https_url(url)?;

        // A HEAD is enough to ask "has this been reached?" without
        // causing another hit to be recorded.
        let response =
            self.agent
                .head(url.trim())
                .call()
                .map_err(|e| CanaryError::NotificationFailed {
                    reason: format!("could not reach {url}: {e}"),
                })?;

        // Any answer from the endpoint counts as reached: the tripwire
        // fires by making the request, not by getting a particular status.
        // Only a transport failure — no DNS, no TLS, no route — means the
        // request never arrived.
        Ok(response.status().is_success())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn https_urls_are_accepted() -> TestResult {
        validate_https_url("https://example.com/canary/abc123")?;
        validate_https_url("https://example.com")?;
        validate_https_url("  https://example.com/x  ")?;
        Ok(())
    }

    #[test]
    fn http_urls_are_rejected() {
        assert!(matches!(
            validate_https_url("http://example.com/canary"),
            Err(CanaryError::InvalidNotifyUrl { .. })
        ));
    }

    #[test]
    fn non_http_schemes_are_rejected() {
        for url in [
            "file:///etc/passwd",
            "ftp://example.com/x",
            "gopher://example.com",
        ] {
            assert!(
                matches!(
                    validate_https_url(url),
                    Err(CanaryError::InvalidNotifyUrl { .. })
                ),
                "{url} should be rejected"
            );
        }
    }

    #[test]
    fn a_url_without_a_host_is_rejected() {
        assert!(matches!(
            validate_https_url("https://"),
            Err(CanaryError::InvalidNotifyUrl { .. })
        ));
        assert!(matches!(
            validate_https_url("https:///canary"),
            Err(CanaryError::InvalidNotifyUrl { .. })
        ));
    }

    #[test]
    fn an_empty_url_is_rejected() {
        assert!(matches!(
            validate_https_url(""),
            Err(CanaryError::InvalidNotifyUrl { .. })
        ));
        assert!(matches!(
            validate_https_url("   "),
            Err(CanaryError::InvalidNotifyUrl { .. })
        ));
    }

    #[test]
    fn notify_rejects_a_non_https_url_before_making_a_request() {
        let notifier = HttpsCanaryNotifier::new();
        // The address is not reachable and the scheme is wrong; the point
        // is that the scheme is what is reported.
        assert!(matches!(
            notifier.notify("http://127.0.0.1:1/canary"),
            Err(CanaryError::InvalidNotifyUrl { .. })
        ));
    }

    #[test]
    fn was_notified_rejects_a_non_https_url_before_making_a_request() {
        let notifier = HttpsCanaryNotifier::new();
        assert!(matches!(
            notifier.was_notified("http://127.0.0.1:1/canary"),
            Err(CanaryError::InvalidNotifyUrl { .. })
        ));
    }
}
