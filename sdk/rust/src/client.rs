use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

use crate::types::*;

/// Parse a 402 response's WWW-Authenticate header to extract the confidential challenge.
///
/// Expected format:
/// ```text
/// Payment id="inv_7x9k", method="tempo", intent="charge",
///   request="base64url...", stealth-meta="st:eth:0x..."
/// ```
pub fn parse_confidential_challenge(www_authenticate: &str) -> Option<ConfidentialChallenge> {
    if !www_authenticate.starts_with("Payment") {
        return None;
    }

    let params_str = &www_authenticate["Payment".len()..];
    let params = parse_auth_params(params_str);

    let stealth_meta = params.get("stealth-meta")?;

    Some(ConfidentialChallenge {
        id: params.get("id").cloned().unwrap_or_default(),
        method: params
            .get("method")
            .cloned()
            .unwrap_or_else(|| "tempo".to_string()),
        intent: params
            .get("intent")
            .cloned()
            .unwrap_or_else(|| "charge".to_string()),
        request: params.get("request").cloned().unwrap_or_default(),
        stealth_meta: stealth_meta.clone(),
    })
}

/// Build the Authorization header value from a challenge ID and credential.
pub fn build_authorization_header(challenge_id: &str, credential: &str) -> String {
    format!("Payment id=\"{challenge_id}\", credential=\"{credential}\"")
}

/// Base64url-encode a string (for building credentials from tx hashes).
pub fn base64url_encode(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

/// Parse key="value" pairs from an auth header string.
fn parse_auth_params(s: &str) -> std::collections::HashMap<String, String> {
    let mut params = std::collections::HashMap::new();
    // Match key="value" patterns
    let re_pattern = regex_lite(s);
    for (key, value) in re_pattern {
        params.insert(key, value);
    }
    params
}

/// Simple key="value" parser (no regex dependency needed).
fn regex_lite(s: &str) -> Vec<(String, String)> {
    let mut results = Vec::new();
    let mut chars = s.chars().peekable();

    loop {
        // Skip whitespace and commas
        while chars
            .peek()
            .is_some_and(|c| c.is_whitespace() || *c == ',')
        {
            chars.next();
        }

        if chars.peek().is_none() {
            break;
        }

        // Read key (alphanumeric + hyphens + underscores)
        let mut key = String::new();
        while chars
            .peek()
            .is_some_and(|c| c.is_alphanumeric() || *c == '-' || *c == '_')
        {
            key.push(chars.next().unwrap());
        }

        if key.is_empty() {
            // Skip unknown character
            chars.next();
            continue;
        }

        // Skip whitespace
        while chars.peek().is_some_and(|c| c.is_whitespace()) {
            chars.next();
        }

        // Expect '='
        if chars.peek() != Some(&'=') {
            continue;
        }
        chars.next(); // consume '='

        // Skip whitespace
        while chars.peek().is_some_and(|c| c.is_whitespace()) {
            chars.next();
        }

        // Expect '"'
        if chars.peek() != Some(&'"') {
            continue;
        }
        chars.next(); // consume opening '"'

        // Read value until closing '"'
        let mut value = String::new();
        while chars.peek().is_some_and(|c| *c != '"') {
            value.push(chars.next().unwrap());
        }

        // Consume closing '"'
        if chars.peek() == Some(&'"') {
            chars.next();
        }

        results.push((key, value));
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_confidential_challenge() {
        let header = r#"Payment id="inv_7x9k", method="tempo", intent="charge", request="eyJ0eXBlIjoiY2hhcmdlIn0", stealth-meta="st:eth:0xaabbccdd""#;

        let challenge = parse_confidential_challenge(header).unwrap();
        assert_eq!(challenge.id, "inv_7x9k");
        assert_eq!(challenge.method, "tempo");
        assert_eq!(challenge.intent, "charge");
        assert_eq!(challenge.request, "eyJ0eXBlIjoiY2hhcmdlIn0");
        assert_eq!(challenge.stealth_meta, "st:eth:0xaabbccdd");
    }

    #[test]
    fn test_parse_non_payment_header() {
        let header = "Bearer token=abc123";
        assert!(parse_confidential_challenge(header).is_none());
    }

    #[test]
    fn test_parse_payment_without_stealth_meta() {
        let header = r#"Payment id="inv_123", method="tempo""#;
        assert!(parse_confidential_challenge(header).is_none());
    }

    #[test]
    fn test_build_authorization_header() {
        let header = build_authorization_header("inv_7x9k", "dHhoYXNo");
        assert_eq!(
            header,
            r#"Payment id="inv_7x9k", credential="dHhoYXNo""#
        );
    }

    #[test]
    fn test_base64url_encode() {
        let data = b"0xabcdef1234567890";
        let encoded = base64url_encode(data);
        // Should be valid base64url (no padding, URL-safe chars)
        assert!(!encoded.contains('+'));
        assert!(!encoded.contains('/'));
        assert!(!encoded.contains('='));
    }
}
