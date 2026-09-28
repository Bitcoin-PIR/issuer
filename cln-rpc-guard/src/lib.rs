//! `bpir-cln-rpc-guard`: a method-and-parameter allowlist in front of Core
//! Lightning's JSON-RPC Unix socket.
//!
//! The CLN socket has no authentication: whoever can open it holds every RPC
//! method. The guard opens the real socket itself (it runs in the socket's
//! group) and exposes a second socket to the issuer, forwarding only
//! `invoice`, `listinvoices`, and `waitinvoice` requests whose parameters pass
//! [`Policy`]. Everything else is answered with a JSON-RPC error and never
//! reaches the node. Responses flow back byte for byte.
//!
//! Framing follows CLN: a request is one JSON object, requests may be
//! concatenated, and the node terminates every response with a blank line.
//! The guard forwards the original bytes of each accepted request unchanged.

pub mod proxy;

use serde_json::{Map, Value};
use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Parameter bounds for the forwarded methods.
#[derive(Clone, Debug)]
pub struct Policy {
    /// Every `label` must start with this prefix (also on `listinvoices` and
    /// `waitinvoice`), so the issuer can never touch the mint's invoices.
    pub label_prefix: String,
    /// Inclusive bounds on `invoice.amount_msat`.
    pub min_msat: u64,
    pub max_msat: u64,
    /// Inclusive upper bound on `invoice.expiry` (seconds).
    pub max_expiry_secs: u64,
    /// Upper bound on the `description` string, whose hash becomes the BOLT11
    /// description hash (x402 request binding).
    pub max_description_bytes: usize,
    pub max_label_bytes: usize,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            label_prefix: "bpir-x402-".to_owned(),
            min_msat: 1_000,
            max_msat: 100_000_000,
            max_expiry_secs: 3_600,
            max_description_bytes: 4_096,
            max_label_bytes: 128,
        }
    }
}

/// Why a request was not forwarded. `code` follows JSON-RPC: -32600 invalid
/// request, -32601 method not allowed, -32602 invalid params.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rejection {
    pub code: i64,
    pub message: String,
}

impl Rejection {
    fn request(message: impl Into<String>) -> Self {
        Self {
            code: -32600,
            message: message.into(),
        }
    }
    fn method(message: impl Into<String>) -> Self {
        Self {
            code: -32601,
            message: message.into(),
        }
    }
    fn params(message: impl Into<String>) -> Self {
        Self {
            code: -32602,
            message: message.into(),
        }
    }

    /// The JSON-RPC error object the guard writes back for a rejected request,
    /// echoing its `id` (or `null` when the request had none), terminated the
    /// way CLN terminates responses.
    pub fn response_bytes(&self, id: Option<&Value>) -> Vec<u8> {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": id.cloned().unwrap_or(Value::Null),
            "error": { "code": self.code, "message": format!("cln-rpc-guard: {}", self.message) },
        });
        let mut out = serde_json::to_vec(&body).expect("static JSON serializes");
        out.extend_from_slice(b"\n\n");
        out
    }
}

/// Checks one parsed request against the allowlist. `Ok(method)` means
/// forward it unchanged.
pub fn check(request: &Value, policy: &Policy) -> Result<&'static str, Rejection> {
    let obj = request
        .as_object()
        .ok_or_else(|| Rejection::request("request is not a JSON object"))?;
    if let Some(v) = obj.get("jsonrpc") {
        if v != "2.0" {
            return Err(Rejection::request("jsonrpc must be \"2.0\""));
        }
    }
    if !obj.contains_key("id") {
        return Err(Rejection::request("request has no id"));
    }
    for key in obj.keys() {
        if !matches!(
            key.as_str(),
            "jsonrpc" | "id" | "method" | "params" | "filter"
        ) {
            return Err(Rejection::request(format!(
                "unknown request member {key:?}"
            )));
        }
    }
    if let Some(filter) = obj.get("filter") {
        if !filter.is_object() {
            return Err(Rejection::request("filter must be an object"));
        }
    }
    let method = obj
        .get("method")
        .and_then(Value::as_str)
        .ok_or_else(|| Rejection::request("method must be a string"))?;
    let params = match obj.get("params") {
        None | Some(Value::Null) => None,
        Some(Value::Object(m)) => Some(m),
        Some(_) => {
            return Err(Rejection::params(
                "params must be an object (named parameters)",
            ))
        }
    };
    match method {
        "invoice" => {
            let p = params.ok_or_else(|| Rejection::params("invoice needs params"))?;
            check_invoice(p, policy)?;
            Ok("invoice")
        }
        "listinvoices" => {
            let p = params.ok_or_else(|| Rejection::params("listinvoices needs one filter"))?;
            check_listinvoices(p, policy)?;
            Ok("listinvoices")
        }
        "waitinvoice" => {
            let p = params.ok_or_else(|| Rejection::params("waitinvoice needs a label"))?;
            only_keys(p, &["label"])?;
            label(p, policy)?;
            Ok("waitinvoice")
        }
        other => Err(Rejection::method(format!(
            "method {other:?} is not allowed"
        ))),
    }
}

fn only_keys(p: &Map<String, Value>, allowed: &[&str]) -> Result<(), Rejection> {
    for key in p.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(Rejection::params(format!(
                "parameter {key:?} is not allowed"
            )));
        }
    }
    Ok(())
}

fn label<'a>(p: &'a Map<String, Value>, policy: &Policy) -> Result<&'a str, Rejection> {
    let label = p
        .get("label")
        .and_then(Value::as_str)
        .ok_or_else(|| Rejection::params("label must be a string"))?;
    if label.len() > policy.max_label_bytes {
        return Err(Rejection::params("label is too long"));
    }
    if !label.starts_with(&policy.label_prefix) || label.len() == policy.label_prefix.len() {
        return Err(Rejection::params(format!(
            "label must start with {:?} and continue",
            policy.label_prefix
        )));
    }
    if !label
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
    {
        return Err(Rejection::params(
            "label has characters outside [A-Za-z0-9._:-]",
        ));
    }
    Ok(label)
}

fn u64_field(p: &Map<String, Value>, key: &str) -> Result<Option<u64>, Rejection> {
    match p.get(key) {
        None => Ok(None),
        Some(Value::Number(n)) => n
            .as_u64()
            .map(Some)
            .ok_or_else(|| Rejection::params(format!("{key} must be a non-negative integer"))),
        Some(_) => Err(Rejection::params(format!("{key} must be an integer"))),
    }
}

fn check_invoice(p: &Map<String, Value>, policy: &Policy) -> Result<(), Rejection> {
    only_keys(
        p,
        &[
            "amount_msat",
            "label",
            "description",
            "expiry",
            "deschashonly",
            "exposeprivatechannels",
            "cltv",
        ],
    )?;
    let amount = u64_field(p, "amount_msat")?
        .ok_or_else(|| Rejection::params("amount_msat is required (integer millisatoshi)"))?;
    if amount < policy.min_msat || amount > policy.max_msat {
        return Err(Rejection::params(format!(
            "amount_msat {amount} outside [{}, {}]",
            policy.min_msat, policy.max_msat
        )));
    }
    label(p, policy)?;
    let description = p
        .get("description")
        .and_then(Value::as_str)
        .ok_or_else(|| Rejection::params("description must be a string"))?;
    if description.is_empty() || description.len() > policy.max_description_bytes {
        return Err(Rejection::params("description is empty or too long"));
    }
    let expiry =
        u64_field(p, "expiry")?.ok_or_else(|| Rejection::params("expiry is required (seconds)"))?;
    if expiry == 0 || expiry > policy.max_expiry_secs {
        return Err(Rejection::params(format!(
            "expiry {expiry} outside [1, {}]",
            policy.max_expiry_secs
        )));
    }
    if p.get("deschashonly") != Some(&Value::Bool(true)) {
        return Err(Rejection::params(
            "deschashonly must be true (description-hash invoices only)",
        ));
    }
    if let Some(v) = p.get("exposeprivatechannels") {
        if !v.is_boolean() {
            return Err(Rejection::params("exposeprivatechannels must be a boolean"));
        }
    }
    if let Some(cltv) = u64_field(p, "cltv")? {
        if cltv == 0 || cltv > 2016 {
            return Err(Rejection::params("cltv outside [1, 2016]"));
        }
    }
    Ok(())
}

fn check_listinvoices(p: &Map<String, Value>, policy: &Policy) -> Result<(), Rejection> {
    only_keys(p, &["label", "payment_hash", "invstring"])?;
    if p.len() != 1 {
        return Err(Rejection::params(
            "listinvoices needs exactly one of label, payment_hash, invstring",
        ));
    }
    if p.contains_key("label") {
        label(p, policy)?;
    } else if let Some(h) = p.get("payment_hash") {
        let h = h
            .as_str()
            .ok_or_else(|| Rejection::params("payment_hash must be a string"))?;
        if h.len() != 64 || !h.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            return Err(Rejection::params(
                "payment_hash must be 64 lowercase hex characters",
            ));
        }
    } else if let Some(s) = p.get("invstring") {
        let s = s
            .as_str()
            .ok_or_else(|| Rejection::params("invstring must be a string"))?;
        if s.is_empty() || s.len() > 2_048 || !s.is_ascii() {
            return Err(Rejection::params(
                "invstring is empty, too long, or not ASCII",
            ));
        }
    }
    Ok(())
}

/// Sliding-window limit on forwarded `invoice` calls, so a compromised issuer
/// cannot fill the node's invoice database.
#[derive(Debug)]
pub struct InvoiceLimiter {
    per_minute: usize,
    recent: VecDeque<Instant>,
}

impl InvoiceLimiter {
    pub fn new(per_minute: usize) -> Self {
        Self {
            per_minute,
            recent: VecDeque::new(),
        }
    }

    /// Records one call at `now` if the window has room.
    pub fn admit(&mut self, now: Instant) -> bool {
        while let Some(front) = self.recent.front() {
            if now.duration_since(*front) >= Duration::from_secs(60) {
                self.recent.pop_front();
            } else {
                break;
            }
        }
        if self.recent.len() >= self.per_minute {
            return false;
        }
        self.recent.push_back(now);
        true
    }
}

/// Incremental splitter for a stream of concatenated JSON values, the way CLN
/// clients write requests. Returns the byte range of the next complete value,
/// `Ok(None)` when more bytes are needed, and an error for malformed JSON.
pub fn next_json_object(buf: &[u8]) -> Result<Option<(usize, usize, Value)>, serde_json::Error> {
    let start = buf
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .unwrap_or(buf.len());
    if start == buf.len() {
        return Ok(None);
    }
    let mut stream = serde_json::Deserializer::from_slice(&buf[start..]).into_iter::<Value>();
    match stream.next() {
        None => Ok(None),
        Some(Ok(value)) => Ok(Some((start, start + stream.byte_offset(), value))),
        Some(Err(e)) if e.is_eof() => Ok(None),
        Some(Err(e)) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn invoice_params() -> Value {
        json!({
            "amount_msat": 1_000_000,
            "label": "bpir-x402-abc",
            "description": "{\"domain\":\"x402:exact:lnbtc:bolt11:http:1\"}",
            "expiry": 900,
            "deschashonly": true
        })
    }

    #[test]
    fn allows_a_bound_invoice() {
        let req = json!({"jsonrpc":"2.0","id":1,"method":"invoice","params":invoice_params()});
        assert_eq!(check(&req, &Policy::default()), Ok("invoice"));
    }

    #[test]
    fn rejects_other_methods_and_positional_params() {
        let policy = Policy::default();
        let pay = json!({"jsonrpc":"2.0","id":1,"method":"pay","params":{"bolt11":"lnbc1"}});
        assert_eq!(check(&pay, &policy).unwrap_err().code, -32601);
        let positional =
            json!({"jsonrpc":"2.0","id":1,"method":"invoice","params":[1000, "bpir-x402-a", "d"]});
        assert_eq!(check(&positional, &policy).unwrap_err().code, -32602);
        let no_id = json!({"jsonrpc":"2.0","method":"invoice","params":invoice_params()});
        assert_eq!(check(&no_id, &policy).unwrap_err().code, -32600);
    }

    #[test]
    fn rejects_invoice_parameter_escapes() {
        let policy = Policy::default();
        let mut cases = Vec::new();
        let mut p = invoice_params();
        p["preimage"] = json!("00".repeat(32));
        cases.push(("preimage", p));
        let mut p = invoice_params();
        p["deschashonly"] = json!(false);
        cases.push(("inline description", p));
        let mut p = invoice_params();
        p["label"] = json!("mint-quote-1");
        cases.push(("foreign label", p));
        let mut p = invoice_params();
        p["expiry"] = json!(86_400);
        cases.push(("long expiry", p));
        let mut p = invoice_params();
        p["amount_msat"] = json!("1000msat");
        cases.push(("string amount", p));
        let mut p = invoice_params();
        p["fallbacks"] = json!(["bc1q..."]);
        cases.push(("fallback address", p));
        for (name, params) in cases {
            let req = json!({"jsonrpc":"2.0","id":1,"method":"invoice","params":params});
            assert_eq!(check(&req, &policy).unwrap_err().code, -32602, "{name}");
        }
    }

    #[test]
    fn listinvoices_needs_exactly_one_scoped_filter() {
        let policy = Policy::default();
        let all = json!({"jsonrpc":"2.0","id":1,"method":"listinvoices","params":{}});
        assert_eq!(check(&all, &policy).unwrap_err().code, -32602);
        let foreign =
            json!({"jsonrpc":"2.0","id":1,"method":"listinvoices","params":{"label":"mint-1"}});
        assert_eq!(check(&foreign, &policy).unwrap_err().code, -32602);
        let by_hash = json!({"jsonrpc":"2.0","id":1,"method":"listinvoices","params":{"payment_hash":"ab".repeat(32)}});
        assert_eq!(check(&by_hash, &policy), Ok("listinvoices"));
        let wait = json!({"jsonrpc":"2.0","id":"w","method":"waitinvoice","params":{"label":"bpir-x402-1"}});
        assert_eq!(check(&wait, &policy), Ok("waitinvoice"));
    }

    #[test]
    fn splits_concatenated_requests_and_waits_for_partial_ones() {
        let a = br#"{"id":1,"method":"x"}"#;
        let b = br#"  {"id":2,"method":"y"}"#;
        let mut buf = Vec::new();
        buf.extend_from_slice(a);
        buf.extend_from_slice(b);
        let (s, e, v) = next_json_object(&buf).unwrap().unwrap();
        assert_eq!((s, e), (0, a.len()));
        assert_eq!(v["id"], 1);
        let (s2, e2, v2) = next_json_object(&buf[e..]).unwrap().unwrap();
        assert_eq!((s2, e2), (2, b.len()));
        assert_eq!(v2["id"], 2);
        assert!(next_json_object(&buf[..5]).unwrap().is_none());
        assert!(next_json_object(b"   ").unwrap().is_none());
        assert!(next_json_object(b"{]").is_err());
    }

    #[test]
    fn limiter_admits_per_minute_then_refuses() {
        let mut l = InvoiceLimiter::new(2);
        let t0 = Instant::now();
        assert!(l.admit(t0));
        assert!(l.admit(t0));
        assert!(!l.admit(t0 + Duration::from_secs(30)));
        assert!(l.admit(t0 + Duration::from_secs(61)));
    }
}
