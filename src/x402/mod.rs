//! x402 `exact` on Bitcoin Lightning (`lnbtc`), as a way to buy a credential
//! pack: `specs/schemes/exact/scheme_exact_lnbtc.md` and
//! `specs/transports-v2/http.md` in x402-foundation/x402 (spec merged
//! 2026-09-23).
//!
//! Roles inside this one process, kept apart by module:
//! - [`binding`]: the `http:1` request binding (JCS object → request hash);
//! - [`receiver`]: creates and looks up invoices through `bpir-cln-rpc-guard`
//!   (the only Lightning-facing code, and it never sees the node socket);
//! - [`invoice`]: strict BOLT11 checks against a payment requirement;
//! - [`facilitator`]: the `/settle` logic (proof + replay protection), pure
//!   over its inputs so it could move to its own process unchanged.
//!
//! The issuer is the x402 *resource server*: `POST /v2/credentials` without a
//! Cashu token is answered `402` with a fresh request-bound invoice; a retry
//! carrying the preimage in `PAYMENT-SIGNATURE` settles and issues the
//! credential. The same invoice is shown as a QR code for a human payer, and
//! `GET /v2/x402/invoices/{payment_hash}` reports its state (and the preimage
//! once paid) so the browser can complete the identical retry.

pub mod binding;
pub mod facilitator;
pub mod invoice;
pub mod limit;
pub mod receiver;
pub mod server;

#[cfg(test)]
mod tests;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// Mainnet and testnet identifiers: `lnbtc:` + first 32 hex characters of the
/// genesis block hash (BIP-122 CAIP-2 convention).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Network {
    Mainnet,
    Testnet,
}

impl Network {
    pub const fn caip2(self) -> &'static str {
        match self {
            Network::Mainnet => "lnbtc:000000000019d6689c085ae165831e93",
            Network::Testnet => "lnbtc:000000000933ea01ad0ee984209779ba",
        }
    }

    pub fn from_caip2(id: &str) -> Option<Self> {
        match id {
            "lnbtc:000000000019d6689c085ae165831e93" => Some(Network::Mainnet),
            "lnbtc:000000000933ea01ad0ee984209779ba" => Some(Network::Testnet),
            _ => None,
        }
    }
}

pub const SCHEME: &str = "exact";
pub const ASSET: &str = "BTC";
pub const PAYMENT_FLOW: &str = "upfront";
pub const ASSET_TRANSFER_METHOD: &str = "bolt11";
pub const PROFILE_HTTP1: &str = "http:1";
pub const X402_VERSION: u64 = 2;

/// Core `PaymentRequirements` (x402 v2 §5.1.2). `extra` carries the scheme
/// fields: `paymentFlow`, `requestHash`, `requestBindingProfile`,
/// `requestBindingParams`, `invoice`, optional `assetTransferMethod`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentRequirements {
    pub scheme: String,
    pub network: String,
    pub amount: String,
    pub asset: String,
    pub pay_to: String,
    pub max_timeout_seconds: u64,
    #[serde(default)]
    pub extra: Map<String, Value>,
}

impl PaymentRequirements {
    pub fn extra_str(&self, key: &str) -> Option<&str> {
        self.extra.get(key).and_then(Value::as_str)
    }
}

/// `ResourceInfo` (x402 v2 §5.1.2).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceInfo {
    pub url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_name: Option<String>,
}

/// The `PaymentRequired` object carried base64-encoded in the
/// `PAYMENT-REQUIRED` header of a 402 (and, here, in the JSON body too).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentRequired {
    pub x402_version: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub resource: ResourceInfo,
    pub accepts: Vec<PaymentRequirements>,
}

/// The `PaymentPayload` a client sends base64-encoded in `PAYMENT-SIGNATURE`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentPayload {
    pub x402_version: u64,
    #[serde(default)]
    pub resource: Option<ResourceInfo>,
    pub accepted: PaymentRequirements,
    pub payload: Map<String, Value>,
}

/// `SettlementResponse` (x402 v2 §5.3), sent base64-encoded in
/// `PAYMENT-RESPONSE`. `payer` is always omitted for Lightning.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SettlementResponse {
    pub success: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_reason: Option<String>,
    pub transaction: String,
    pub network: String,
}

impl SettlementResponse {
    pub fn failure(network: &str, reason: &str) -> Self {
        Self {
            success: false,
            error_reason: Some(reason.to_owned()),
            transaction: String::new(),
            network: network.to_owned(),
        }
    }
}

/// Base64 (standard alphabet, padded) of a JSON value, the header encoding.
pub fn header_value<T: Serialize>(value: &T) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .encode(serde_json::to_vec(value).expect("serializable"))
}

/// Decodes a base64 JSON header. Both padded and unpadded input are accepted.
pub fn parse_header<T: for<'de> Deserialize<'de>>(header: &str) -> Result<T, String> {
    use base64::Engine as _;
    let trimmed = header.trim();
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(trimmed)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(trimmed))
        .map_err(|e| format!("base64: {e}"))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("json: {e}"))
}

pub fn is_lower_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}
