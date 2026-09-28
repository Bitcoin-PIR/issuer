//! Receiver adapter: creates and looks up invoices through the guard socket
//! (`bpir-cln-rpc-guard`), speaking CLN's JSON-RPC framing. This is the only
//! Lightning-facing code in the issuer, and the guard limits it to `invoice`,
//! `listinvoices`, and `waitinvoice` with bounded parameters.

use async_trait::async_trait;
use serde_json::{json, Value};
use std::path::PathBuf;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreatedInvoice {
    pub bolt11: String,
    pub payment_hash_hex: String,
    pub label: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvoiceState {
    pub label: String,
    /// CLN: `unpaid`, `paid`, or `expired`.
    pub status: String,
    pub bolt11: Option<String>,
    pub preimage_hex: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum ReceiverError {
    #[error("guard socket: {0}")]
    Io(#[from] std::io::Error),
    #[error("guard answer: {0}")]
    Protocol(String),
    #[error("node refused ({code}): {message}")]
    Rpc { code: i64, message: String },
}

/// What the resource server needs from the Lightning side.
#[async_trait]
pub trait InvoiceSource: Send + Sync {
    /// A fresh invoice for exactly `amount_msat`, whose BOLT11 `h` field is
    /// SHA-256 of `description` (CLN `deschashonly`), expiring after
    /// `expiry_secs`.
    async fn create_invoice(
        &self,
        amount_msat: u64,
        description: &str,
        expiry_secs: u64,
    ) -> Result<CreatedInvoice, ReceiverError>;

    /// State of one invoice by payment hash, if the node knows it.
    async fn lookup(&self, payment_hash_hex: &str) -> Result<Option<InvoiceState>, ReceiverError>;
}

/// The production adapter over the guard's Unix socket.
pub struct GuardReceiver {
    socket: PathBuf,
    label_prefix: String,
}

impl GuardReceiver {
    pub fn new(socket: PathBuf, label_prefix: String) -> Self {
        Self {
            socket,
            label_prefix,
        }
    }

    fn fresh_label(&self) -> Result<String, ReceiverError> {
        let mut nonce = [0u8; 12];
        getrandom::getrandom(&mut nonce)
            .map_err(|e| ReceiverError::Protocol(format!("randomness: {e}")))?;
        Ok(format!("{}{}", self.label_prefix, hex::encode(nonce)))
    }

    async fn call(&self, method: &str, params: Value) -> Result<Value, ReceiverError> {
        let mut stream = UnixStream::connect(&self.socket).await?;
        let request = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
        stream
            .write_all(&serde_json::to_vec(&request).expect("json"))
            .await?;
        let mut buf = Vec::new();
        let mut chunk = [0u8; 8192];
        let body = loop {
            if let Some(pos) = buf.windows(2).position(|w| w == b"\n\n") {
                break buf[..pos].to_vec();
            }
            let n = stream.read(&mut chunk).await?;
            if n == 0 {
                if buf.is_empty() {
                    return Err(ReceiverError::Protocol("closed without an answer".into()));
                }
                break buf.clone();
            }
            buf.extend_from_slice(&chunk[..n]);
            if buf.len() > 1 << 20 {
                return Err(ReceiverError::Protocol("answer larger than 1 MiB".into()));
            }
        };
        let answer: Value =
            serde_json::from_slice(&body).map_err(|e| ReceiverError::Protocol(e.to_string()))?;
        if let Some(err) = answer.get("error") {
            return Err(ReceiverError::Rpc {
                code: err.get("code").and_then(Value::as_i64).unwrap_or(0),
                message: err
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_owned(),
            });
        }
        answer
            .get("result")
            .cloned()
            .ok_or_else(|| ReceiverError::Protocol("answer without result".into()))
    }
}

#[async_trait]
impl InvoiceSource for GuardReceiver {
    async fn create_invoice(
        &self,
        amount_msat: u64,
        description: &str,
        expiry_secs: u64,
    ) -> Result<CreatedInvoice, ReceiverError> {
        let label = self.fresh_label()?;
        let result = self
            .call(
                "invoice",
                json!({
                    "amount_msat": amount_msat,
                    "label": label,
                    "description": description,
                    "expiry": expiry_secs,
                    "deschashonly": true,
                }),
            )
            .await?;
        let bolt11 = result
            .get("bolt11")
            .and_then(Value::as_str)
            .ok_or_else(|| ReceiverError::Protocol("invoice answer without bolt11".into()))?
            .to_owned();
        let payment_hash_hex = result
            .get("payment_hash")
            .and_then(Value::as_str)
            .ok_or_else(|| ReceiverError::Protocol("invoice answer without payment_hash".into()))?
            .to_owned();
        Ok(CreatedInvoice {
            bolt11,
            payment_hash_hex,
            label,
        })
    }

    async fn lookup(&self, payment_hash_hex: &str) -> Result<Option<InvoiceState>, ReceiverError> {
        let result = self
            .call("listinvoices", json!({"payment_hash": payment_hash_hex}))
            .await?;
        let Some(entry) = result
            .get("invoices")
            .and_then(Value::as_array)
            .and_then(|a| a.first())
        else {
            return Ok(None);
        };
        let field = |k: &str| entry.get(k).and_then(Value::as_str).map(str::to_owned);
        Ok(Some(InvoiceState {
            label: field("label").unwrap_or_default(),
            status: field("status").unwrap_or_default(),
            bolt11: field("bolt11"),
            preimage_hex: field("payment_preimage"),
        }))
    }
}
