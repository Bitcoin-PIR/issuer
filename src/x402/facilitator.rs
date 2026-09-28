//! The x402 facilitator `/settle` logic for `exact` on `lnbtc`: compares the
//! accepted requirement with the server's, checks the accepted invoice and
//! the preimage, and hands back the consumption key the caller must insert
//! atomically into its replay store (`duplicate_settlement` if present).
//! Pure over its inputs; it never talks to a node.

use super::binding::validate_http1_params;
use super::invoice::{self, Expected};
use super::{
    is_lower_hex, Network, PaymentPayload, PaymentRequirements, ASSET, ASSET_TRANSFER_METHOD,
    PAYMENT_FLOW, PROFILE_HTTP1, SCHEME,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// A proof that passed every check. `replay_key` is `network:payment_hash`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settled {
    pub network: Network,
    pub payment_hash_hex: String,
    pub replay_key: String,
    pub amount_msat: u64,
    /// `invoice_end + skew`: the replay entry must outlive this by an hour.
    pub retain_until: u64,
}

/// Runs the facilitator checks 1–7 of the scheme spec. `now_unix` is the
/// settlement time. Errors are the spec's `errorReason` strings.
pub fn settle(
    requirements: &PaymentRequirements,
    payload: &PaymentPayload,
    now_unix: u64,
    clock_skew_secs: u64,
) -> Result<Settled, &'static str> {
    let accepted = &payload.accepted;
    // 1. Core fields equal.
    if accepted.scheme != requirements.scheme {
        return Err("unsupported_scheme");
    }
    if accepted.network != requirements.network {
        return Err("network_mismatch");
    }
    if accepted.amount != requirements.amount {
        return Err("invalid_exact_lnbtc_amount_mismatch");
    }
    if accepted.asset != requirements.asset {
        return Err("invalid_exact_lnbtc_asset");
    }
    if accepted.pay_to != requirements.pay_to {
        return Err("invalid_exact_lnbtc_pay_to_mismatch");
    }
    if accepted.max_timeout_seconds != requirements.max_timeout_seconds {
        return Err("invalid_exact_lnbtc_max_timeout_mismatch");
    }
    // 2. Well-formed terms.
    if requirements.scheme != SCHEME {
        return Err("unsupported_scheme");
    }
    let network = Network::from_caip2(&requirements.network).ok_or("unsupported_network")?;
    if requirements.asset != ASSET {
        return Err("invalid_exact_lnbtc_asset");
    }
    let amount_msat = parse_amount(&requirements.amount).ok_or("invalid_exact_lnbtc_amount")?;
    if requirements.max_timeout_seconds == 0 {
        return Err("invalid_exact_lnbtc_max_timeout");
    }
    if !is_lower_hex(&requirements.pay_to, 66)
        || !(requirements.pay_to.starts_with("02") || requirements.pay_to.starts_with("03"))
    {
        return Err("invalid_exact_lnbtc_pay_to_malformed");
    }
    // 3. Scheme extras on both sides.
    for side in [requirements, accepted] {
        let method = side
            .extra_str("assetTransferMethod")
            .unwrap_or(ASSET_TRANSFER_METHOD);
        if method != ASSET_TRANSFER_METHOD {
            return Err("invalid_exact_lnbtc_asset_transfer_method");
        }
        if side.extra_str("paymentFlow") != Some(PAYMENT_FLOW) {
            return Err("invalid_exact_lnbtc_payment_flow");
        }
        let hash = side
            .extra_str("requestHash")
            .ok_or("invalid_exact_lnbtc_request_binding")?;
        if !is_lower_hex(hash, 64) {
            return Err("invalid_exact_lnbtc_request_binding");
        }
        if side.extra_str("requestBindingProfile") != Some(PROFILE_HTTP1) {
            return Err("invalid_exact_lnbtc_request_binding");
        }
        let params = side
            .extra
            .get("requestBindingParams")
            .ok_or("invalid_exact_lnbtc_request_binding")?;
        validate_http1_params(params).map_err(|_| "invalid_exact_lnbtc_request_binding")?;
    }
    if requirements.extra_str("requestHash") != accepted.extra_str("requestHash")
        || requirements.extra_str("requestBindingProfile")
            != accepted.extra_str("requestBindingProfile")
        || jcs(&requirements.extra["requestBindingParams"])
            != jcs(&accepted.extra["requestBindingParams"])
    {
        return Err("invalid_exact_lnbtc_request_mismatch");
    }
    for (key, value) in &requirements.extra {
        if matches!(
            key.as_str(),
            "invoice" | "requestHash" | "requestBindingProfile" | "requestBindingParams"
        ) {
            continue;
        }
        if accepted.extra.get(key) != Some(value) {
            return Err("invalid_exact_lnbtc_extra_mismatch");
        }
    }
    // 4. Invoices present; the accepted one settles.
    let accepted_invoice = accepted
        .extra_str("invoice")
        .filter(|s| !s.trim().is_empty())
        .ok_or("invalid_exact_lnbtc_invoice_missing")?;
    if requirements
        .extra_str("invoice")
        .is_none_or(|s| s.trim().is_empty())
    {
        return Err("invalid_exact_lnbtc_invoice_missing");
    }
    // 5. Strict invoice checks against the server's expected digest.
    let mut request_hash = [0u8; 32];
    hex::decode_to_slice(
        requirements.extra_str("requestHash").unwrap_or_default(),
        &mut request_hash,
    )
    .map_err(|_| "invalid_exact_lnbtc_request_binding")?;
    let facts = invoice::check(
        accepted_invoice,
        &Expected {
            network,
            amount_msat,
            pay_to_hex: &requirements.pay_to,
            request_hash: &request_hash,
            max_timeout_secs: requirements.max_timeout_seconds,
            now_unix,
            clock_skew_secs,
        },
    )?;
    // 6. Preimage.
    let preimage = payload
        .payload
        .get("preimage")
        .ok_or("invalid_exact_lnbtc_preimage_missing")?
        .as_str()
        .ok_or("invalid_exact_lnbtc_preimage_malformed")?;
    if !preimage
        .bytes()
        .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err("invalid_exact_lnbtc_preimage_malformed");
    }
    if preimage.len() != 64 {
        return Err("invalid_exact_lnbtc_preimage_length");
    }
    let preimage_bytes =
        hex::decode(preimage).map_err(|_| "invalid_exact_lnbtc_preimage_malformed")?;
    let digest: [u8; 32] = Sha256::digest(&preimage_bytes).into();
    if digest != facts.payment_hash {
        return Err("invalid_exact_lnbtc_preimage_hash_mismatch");
    }
    // 7. Paid-but-expired window.
    if !facts.within_settlement_window(now_unix, clock_skew_secs) {
        return Err("invalid_exact_lnbtc_invoice_expired");
    }
    let payment_hash_hex = facts.payment_hash_hex();
    Ok(Settled {
        network,
        replay_key: format!("{}:{payment_hash_hex}", network.caip2()),
        payment_hash_hex,
        amount_msat,
        retain_until: facts.end().saturating_add(clock_skew_secs),
    })
}

/// `amount`: decimal string, positive integer, no sign/point/exponent.
pub fn parse_amount(amount: &str) -> Option<u64> {
    if amount.is_empty() || amount.len() > 19 || !amount.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let value: u64 = amount.parse().ok()?;
    (value > 0).then_some(value)
}

fn jcs(value: &Value) -> String {
    serde_jcs::to_string(value).unwrap_or_default()
}
