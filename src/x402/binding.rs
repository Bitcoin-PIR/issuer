//! Request binding for the `http:1` profile: the JCS-canonical binding
//! object whose UTF-8 bytes are the BOLT11 description and whose SHA-256 is
//! the request hash (`extra.requestHash` and the invoice's `h` field).

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub const DOMAIN_HTTP1: &str = "x402:exact:lnbtc:bolt11:http:1";

/// One bound header: its lowercase name and the value as sent, if present.
pub struct BoundHeader<'a> {
    pub name: &'a str,
    pub value: Option<&'a str>,
}

/// The canonical description bytes and their digest for one HTTP request.
pub struct Binding {
    pub description: String,
    pub request_hash: [u8; 32],
}

impl Binding {
    pub fn request_hash_hex(&self) -> String {
        hex::encode(self.request_hash)
    }
}

/// `method` and `url` follow RFC 9421 `@method` / `@target-uri`; `body` is
/// the raw content bytes; `headers` must come in the configured order
/// (ascending ASCII names, no duplicates).
pub fn http1(method: &str, url: &str, body: &[u8], headers: &[BoundHeader<'_>]) -> Binding {
    let body_hash = hex::encode(Sha256::digest(body));
    let headers: Vec<Value> = headers
        .iter()
        .map(|h| {
            let value_hash = match h.value {
                Some(v) => {
                    let mut hasher = Sha256::new();
                    hasher.update([0x01]);
                    hasher.update(v.as_bytes());
                    hasher.finalize()
                }
                None => Sha256::digest([0x00]),
            };
            json!({ "name": h.name, "valueHash": hex::encode(value_hash) })
        })
        .collect();
    let binding = json!({
        "domain": DOMAIN_HTTP1,
        "method": method,
        "url": url,
        "bodyHash": body_hash,
        "headers": headers,
    });
    let description = serde_jcs::to_string(&binding).expect("binding object is plain JSON");
    let request_hash: [u8; 32] = Sha256::digest(description.as_bytes()).into();
    Binding {
        description,
        request_hash,
    }
}

/// Validates a `requestBindingParams` object for `http:1`: exactly one member
/// `headers`, lowercase field-name tokens in ascending byte order, no
/// duplicates, never `payment-signature`.
pub fn validate_http1_params(params: &Value) -> Result<Vec<String>, &'static str> {
    let obj = params
        .as_object()
        .ok_or("requestBindingParams must be an object")?;
    if obj.len() != 1 {
        return Err("requestBindingParams must contain exactly `headers`");
    }
    let headers = obj
        .get("headers")
        .and_then(Value::as_array)
        .ok_or("requestBindingParams.headers must be an array")?;
    let mut names: Vec<String> = Vec::with_capacity(headers.len());
    for h in headers {
        let name = h.as_str().ok_or("header names must be strings")?;
        if name.is_empty()
            || name == "payment-signature"
            || !name.bytes().all(|b| {
                b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_' | b'.')
            })
        {
            return Err("header names must be lowercase field-name tokens (not payment-signature)");
        }
        if let Some(prev) = names.last() {
            if name <= prev.as_str() {
                return Err("header names must be in ascending order without duplicates");
            }
        }
        names.push(name.to_owned());
    }
    Ok(names)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_the_specification_test_vector() {
        let b = http1("GET", "https://api.example.com/article/A", b"", &[]);
        assert_eq!(
            b.description,
            r#"{"bodyHash":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","domain":"x402:exact:lnbtc:bolt11:http:1","headers":[],"method":"GET","url":"https://api.example.com/article/A"}"#
        );
        assert_eq!(
            b.request_hash_hex(),
            "0d6623f775e025501fa7f0a30b54da25aad62b6ccfe35c85da38016711e6c018"
        );
        let other = http1("GET", "https://api.example.com/article/B", b"", &[]);
        assert_eq!(
            other.request_hash_hex(),
            "4a99860f75eed1ea8178a5db488e044173bc570c8a6210f2c8590cdf8622d509"
        );
    }

    #[test]
    fn absent_and_empty_headers_differ_and_body_bytes_count() {
        let absent = http1(
            "POST",
            "https://x/y",
            b"{}",
            &[BoundHeader {
                name: "content-type",
                value: None,
            }],
        );
        let empty = http1(
            "POST",
            "https://x/y",
            b"{}",
            &[BoundHeader {
                name: "content-type",
                value: Some(""),
            }],
        );
        let json = http1(
            "POST",
            "https://x/y",
            b"{}",
            &[BoundHeader {
                name: "content-type",
                value: Some("application/json"),
            }],
        );
        assert_ne!(absent.request_hash, empty.request_hash);
        assert_ne!(empty.request_hash, json.request_hash);
        let spaced = http1(
            "POST",
            "https://x/y",
            b"{ }",
            &[BoundHeader {
                name: "content-type",
                value: Some("application/json"),
            }],
        );
        assert_ne!(
            json.request_hash, spaced.request_hash,
            "bodies are hashed as bytes"
        );
    }

    #[test]
    fn validates_binding_params() {
        assert_eq!(
            validate_http1_params(&json!({"headers": ["accept", "content-type"]})).unwrap(),
            vec!["accept", "content-type"]
        );
        assert!(validate_http1_params(&json!({"headers": []}))
            .unwrap()
            .is_empty());
        assert!(validate_http1_params(&json!({"headers": ["content-type", "accept"]})).is_err());
        assert!(validate_http1_params(&json!({"headers": ["Content-Type"]})).is_err());
        assert!(validate_http1_params(&json!({"headers": ["payment-signature"]})).is_err());
        assert!(validate_http1_params(&json!({"headers": [], "extra": 1})).is_err());
        assert!(validate_http1_params(&json!({})).is_err());
    }
}
