//! The resource-server side of `POST /v2/credentials` over x402: binds the
//! incoming request, asks the receiver for a request-bound invoice, checks it
//! before publishing the challenge, and settles a paid retry through the
//! facilitator logic.

use super::binding::{self, Binding, BoundHeader};
use super::facilitator::{self, Settled};
use super::invoice::{self, Expected};
use super::limit::IpLimiter;
use super::receiver::{InvoiceSource, ReceiverError};
use super::{
    is_lower_hex, Network, PaymentPayload, PaymentRequired, PaymentRequirements, ResourceInfo,
    ASSET, PAYMENT_FLOW, PROFILE_HTTP1, SCHEME, X402_VERSION,
};
use crate::config::X402Config;
use axum::http::HeaderMap;
use serde_json::{json, Map, Value};
use std::time::Instant;
use tokio::sync::Mutex;

pub const CREDENTIALS_PATH: &str = "/v2/credentials";

pub struct X402State {
    pub config: X402Config,
    pub network: Network,
    pub receiver: Box<dyn InvoiceSource>,
    limiter: Mutex<IpLimiter>,
}

/// One incoming request, bound: the digest every side must agree on.
pub struct BoundRequest {
    pub binding: Binding,
    pub resource_url: String,
}

#[derive(Debug, thiserror::Error)]
pub enum ChallengeError {
    #[error("too many fresh invoices; retry later")]
    RateLimited,
    #[error("receiver: {0}")]
    Receiver(#[from] ReceiverError),
    /// The receiver returned an invoice that fails the server-side checks
    /// (a misconfigured `node_pubkey_hex`, most likely).
    #[error("receiver invoice failed {0}")]
    Invalid(&'static str),
}

impl X402State {
    pub fn new(config: X402Config, receiver: Box<dyn InvoiceSource>) -> Result<Self, String> {
        let network = match config.network.as_str() {
            "mainnet" => Network::Mainnet,
            "testnet" => Network::Testnet,
            other => return Err(format!("x402.network {other:?}: use mainnet or testnet")),
        };
        if !is_lower_hex(&config.node_pubkey_hex, 66)
            || !(config.node_pubkey_hex.starts_with("02")
                || config.node_pubkey_hex.starts_with("03"))
        {
            return Err("x402.node_pubkey_hex must be a compressed key, 66 lowercase hex".into());
        }
        if !(config.public_url.starts_with("https://") || config.public_url.starts_with("http://"))
            || config.public_url.ends_with('/')
            || config.public_url.contains('?')
            || config.public_url.contains('#')
        {
            return Err("x402.public_url must be an origin like https://issuer.example".into());
        }
        binding::validate_http1_params(&json!({ "headers": config.bound_headers }))
            .map_err(|e| format!("x402.bound_headers: {e}"))?;
        if config.max_timeout_secs == 0 {
            return Err("x402.max_timeout_secs must be positive".into());
        }
        let limiter = Mutex::new(IpLimiter::new(
            config.invoices_per_minute_per_ip,
            config.invoices_per_minute,
        ));
        Ok(Self {
            config,
            network,
            receiver,
            limiter,
        })
    }

    pub fn resource_url(&self) -> String {
        format!("{}{CREDENTIALS_PATH}", self.config.public_url)
    }

    /// Binds a `POST /v2/credentials` request: the configured public URL,
    /// the raw body bytes, and the configured headers as sent. A bound header
    /// whose value is not visible ASCII is rejected, as the profile requires.
    pub fn bind(&self, headers: &HeaderMap, body: &[u8]) -> Result<BoundRequest, &'static str> {
        let mut bound = Vec::with_capacity(self.config.bound_headers.len());
        for name in &self.config.bound_headers {
            let value = match headers.get(name.as_str()) {
                None => None,
                Some(v) => Some(v.to_str().map_err(|_| "bound header value is not ASCII")?),
            };
            bound.push(BoundHeader { name, value });
        }
        let resource_url = self.resource_url();
        let binding = binding::http1("POST", &resource_url, body, &bound);
        Ok(BoundRequest {
            binding,
            resource_url,
        })
    }

    fn requirements(&self, bound: &BoundRequest, sat: u64, invoice: &str) -> PaymentRequirements {
        let mut extra = Map::new();
        extra.insert("assetTransferMethod".into(), json!("bolt11"));
        extra.insert("paymentFlow".into(), json!(PAYMENT_FLOW));
        extra.insert(
            "requestHash".into(),
            json!(bound.binding.request_hash_hex()),
        );
        extra.insert("requestBindingProfile".into(), json!(PROFILE_HTTP1));
        extra.insert(
            "requestBindingParams".into(),
            json!({ "headers": self.config.bound_headers }),
        );
        extra.insert("invoice".into(), Value::String(invoice.to_owned()));
        PaymentRequirements {
            scheme: SCHEME.into(),
            network: self.network.caip2().into(),
            amount: (sat * 1_000).to_string(),
            asset: ASSET.into(),
            pay_to: self.config.node_pubkey_hex.clone(),
            max_timeout_seconds: self.config.max_timeout_secs,
            extra,
        }
    }

    /// A fresh challenge: one invoice for `sat`, bound to the request.
    pub async fn challenge(
        &self,
        bound: &BoundRequest,
        credits: u64,
        sat: u64,
        now_unix: u64,
        client_ip: &str,
    ) -> Result<PaymentRequired, ChallengeError> {
        if !self.limiter.lock().await.admit(client_ip, Instant::now()) {
            return Err(ChallengeError::RateLimited);
        }
        let created = self
            .receiver
            .create_invoice(
                sat * 1_000,
                &bound.binding.description,
                self.config.max_timeout_secs,
            )
            .await?;
        let facts = invoice::check(
            &created.bolt11,
            &Expected {
                network: self.network,
                amount_msat: sat * 1_000,
                pay_to_hex: &self.config.node_pubkey_hex,
                request_hash: &bound.binding.request_hash,
                max_timeout_secs: self.config.max_timeout_secs,
                now_unix,
                clock_skew_secs: self.config.clock_skew_secs,
            },
        )
        .map_err(ChallengeError::Invalid)?;
        if !facts.is_unexpired_at(now_unix) {
            return Err(ChallengeError::Invalid(
                "invalid_exact_lnbtc_invoice_expired",
            ));
        }
        if facts.payment_hash_hex() != created.payment_hash_hex {
            return Err(ChallengeError::Invalid(
                "invalid_exact_lnbtc_invoice_decode_failed",
            ));
        }
        Ok(PaymentRequired {
            x402_version: X402_VERSION,
            error: Some(
                "payment required: pay the Lightning invoice and retry with PAYMENT-SIGNATURE"
                    .into(),
            ),
            resource: ResourceInfo {
                url: bound.resource_url.clone(),
                description: Some(format!("BitcoinPIR credential pack: {credits} credits")),
                mime_type: Some("application/json".into()),
                service_name: Some("BitcoinPIR issuer".into()),
            },
            accepts: vec![self.requirements(bound, sat, &created.bolt11)],
        })
    }

    /// Settles a paid retry: the requirements are recomputed from the actual
    /// request (never taken from the client echo), then the facilitator
    /// checks the accepted invoice and preimage against them.
    pub fn settle(
        &self,
        bound: &BoundRequest,
        sat: u64,
        payload: &PaymentPayload,
        now_unix: u64,
    ) -> Result<Settled, &'static str> {
        if payload.x402_version != X402_VERSION {
            return Err("unsupported_x402_version");
        }
        let accepted_invoice = payload
            .accepted
            .extra_str("invoice")
            .unwrap_or_default()
            .to_owned();
        let requirements = self.requirements(bound, sat, &accepted_invoice);
        facilitator::settle(
            &requirements,
            payload,
            now_unix,
            self.config.clock_skew_secs,
        )
    }
}
