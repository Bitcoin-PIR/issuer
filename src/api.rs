//! HTTP layer: `GET /v2/info`, `POST /v2/credentials` and `POST /v2/redeem`
//! as `docs/CREDITS.md` specifies, plus `GET /healthz` for the process
//! supervisor.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;

use ed25519_dalek::VerifyingKey;
use pir_credit::arc::{decode_presentations, CredentialRequestV2, CredentialResponseV2};
use pir_credit::issuer::{
    IssuerInfoV2, OfferV2, RateCardEntryV2, RedeemRequestV1, RedeemResponseV1,
    CREDIT_PRESENT_KIND_ARC, CREDIT_PRESENT_KIND_CASHU, ISSUER_API_VERSION,
};

use crate::arc::{ArcError, ArcIssuer};

use crate::cashu::{token_key, SwapError, Swapper, TokenSummary};
use crate::config::Config;
use crate::issuer_key::IssuerKey;
use crate::redeem::{verify_request, RedeemEvent, RedeemStore};
use crate::store::{State as TokenState, Store};
use crate::x402::facilitator::Settled;
use crate::x402::server::{ChallengeError, X402State};
use crate::x402::{self, header_value, parse_header, PaymentPayload, SettlementResponse};

/// x402 HTTP transport headers (`specs/transports-v2/http.md`).
const PAYMENT_REQUIRED: HeaderName = HeaderName::from_static("payment-required");
const PAYMENT_SIGNATURE: HeaderName = HeaderName::from_static("payment-signature");
const PAYMENT_RESPONSE: HeaderName = HeaderName::from_static("payment-response");

/// Tokens are a few kilobytes; anything larger is not a purchase.
const MAX_BODY_BYTES: usize = 64 * 1024;

pub struct AppState {
    pub config: Config,
    pub issuer: IssuerKey,
    pub swapper: Box<dyn Swapper>,
    /// One mutex around the store serializes token handling; the swap is
    /// awaited under it so two concurrent requests for the same token cannot
    /// both reach the mint. Throughput is bounded by mint latency, which is
    /// fine for a service selling a few packs a minute.
    pub store: Mutex<Store>,
    /// Replay index and settlement ledger of `POST /v2/redeem`. Locked
    /// after `store`, never before it.
    pub redeem_store: Mutex<RedeemStore>,
    /// Operator keys whose certified servers may redeem (from
    /// `operator_pubkeys`).
    pub operator_keys: Vec<VerifyingKey>,
    /// x402 `exact/lnbtc` purchase rail; `None` keeps `POST /v2/credentials`
    /// Cashu-only.
    pub x402: Option<X402State>,
    /// ARC issuer (`[arc]`), `None` when credentials are not sold.
    pub arc: Option<ArcIssuer>,
    pub clock: Box<dyn Fn() -> u64 + Send + Sync>,
}

#[derive(Debug, Serialize)]
pub struct ErrorBody {
    pub error: &'static str,
    pub message: String,
}

#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub body: ErrorBody,
}

impl ApiError {
    fn new(status: StatusCode, error: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            body: ErrorBody {
                error,
                message: message.into(),
            },
        }
    }
    pub fn invalid_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "invalid_request", message)
    }
    pub fn wrong_amount(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "wrong_amount", message)
    }
    pub fn mint_not_accepted(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "mint_not_accepted", message)
    }
    pub fn token_rejected(message: impl Into<String>) -> Self {
        Self::new(StatusCode::PAYMENT_REQUIRED, "token_rejected", message)
    }
    pub fn mint_unavailable(message: impl Into<String>) -> Self {
        Self::new(StatusCode::SERVICE_UNAVAILABLE, "mint_unavailable", message)
    }
    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal", message)
    }
    pub fn rate_limited(message: impl Into<String>) -> Self {
        Self::new(StatusCode::TOO_MANY_REQUESTS, "rate_limited", message)
    }
    pub fn receiver_unavailable(message: impl Into<String>) -> Self {
        Self::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "receiver_unavailable",
            message,
        )
    }
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found", message)
    }
    pub fn unauthorized(message: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "unauthorized", message)
    }
    pub fn unsupported_kind(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "unsupported_kind", message)
    }
    pub fn already_redeemed(message: impl Into<String>) -> Self {
        Self::new(StatusCode::PAYMENT_REQUIRED, "already_redeemed", message)
    }
    pub fn expired_epoch(message: impl Into<String>) -> Self {
        Self::new(StatusCode::PAYMENT_REQUIRED, "expired_epoch", message)
    }
    pub fn invalid_presentation(message: impl Into<String>) -> Self {
        Self::new(
            StatusCode::PAYMENT_REQUIRED,
            "invalid_presentation",
            message,
        )
    }
    pub fn double_spend(message: impl Into<String>) -> Self {
        Self::new(StatusCode::PAYMENT_REQUIRED, "double_spend", message)
    }
}

impl From<ArcError> for ApiError {
    fn from(error: ArcError) -> Self {
        match error {
            ArcError::Malformed(..) => ApiError::invalid_request(error.to_string()),
            ArcError::Invalid(..) => ApiError::invalid_presentation(error.to_string()),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(self.body)).into_response()
    }
}

pub fn build_router(state: Arc<AppState>) -> Router {
    let allow_origin = if state.config.cors_origins.is_empty() {
        AllowOrigin::any()
    } else {
        AllowOrigin::list(
            state
                .config
                .cors_origins
                .iter()
                .filter_map(|o| HeaderValue::from_str(o).ok()),
        )
    };
    let cors = CorsLayer::new()
        .allow_origin(allow_origin)
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([header::CONTENT_TYPE, PAYMENT_SIGNATURE])
        .expose_headers([PAYMENT_REQUIRED, PAYMENT_RESPONSE])
        .max_age(std::time::Duration::from_secs(3600));
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/v2/info", get(info_v2))
        .route("/v2/credentials", post(credentials))
        .route("/v2/x402/invoices/{payment_hash}", get(x402_invoice_status))
        .route("/v2/redeem", post(redeem))
        .layer(RequestBodyLimitLayer::new(MAX_BODY_BYTES))
        .layer(cors)
        .with_state(state)
}

/// `GET /v2/info` (docs/CREDITS.md): the credits contract parameters,
/// sat-priced offers, and the informational rate card.
async fn info_v2(State(state): State<Arc<AppState>>) -> Json<IssuerInfoV2> {
    let gas = state.config.gas.params();
    let now = (state.clock)();
    // Offers are credential packs; without ARC there is nothing to buy up
    // front (Cashu tokens are presented directly).
    let offers = match (&state.config.arc, &state.arc) {
        (Some(config), Some(_)) => config
            .credential_offers
            .iter()
            .map(|offer| OfferV2 {
                credits: offer.credits,
                sat: offer.sat,
            })
            .collect(),
        _ => Vec::new(),
    };
    Json(IssuerInfoV2 {
        service: "bitcoinpir-issuer".to_owned(),
        version: ISSUER_API_VERSION,
        credit_sat: gas.credit_sat,
        gas_per_credit: gas.gas_per_credit,
        base_gas_per_frame: gas.base_gas_per_frame,
        egress_gas_per_mb: gas.egress_gas_per_mb,
        mints: state.config.mints.clone(),
        offers,
        arc: state.arc.as_ref().map(|arc| arc.info(now)),
        rate_card: state
            .config
            .rate_card
            .iter()
            .map(|entry| RateCardEntryV2 {
                flow: entry.flow.clone(),
                credits: entry.credits,
            })
            .collect(),
    })
}

/// `POST /v2/redeem` (docs/CREDITS.md): authenticate the server, settle
/// every item, book the value, answer with signed gas. All or nothing: an
/// item the mint refuses fails the whole request and nothing is booked.
async fn redeem(
    State(state): State<Arc<AppState>>,
    body: Result<Json<RedeemRequestV1>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<RedeemResponseV1>, ApiError> {
    let Json(request) = body.map_err(|e| ApiError::invalid_request(format!("body: {e}")))?;
    let now = (state.clock)();
    let verified = verify_request(
        &request,
        &state.operator_keys,
        now,
        state.config.redeem_max_skew_secs,
    )?;
    let gas = state.config.gas.params();

    // Lock order: token store first, redeem store second (see AppState).
    let mut store = state.store.lock().await;
    let mut redeem_store = state.redeem_store.lock().await;
    if let Some(answer) = redeem_store.answer(&verified.server_id, &verified.nonce_hex) {
        tracing::info!(server_id = %verified.server_id, "replaying a redeem answer for a nonce seen before");
        return Ok(Json(answer));
    }

    let mut gas_added: u64 = 0;
    let mut sat_value: u64 = 0;
    let mut items_accepted: u32 = 0;
    let mut consumed_epoch: Option<u32> = None;
    let mut consumed_tags: Vec<String> = Vec::new();
    for (kind, payload) in &verified.items {
        match *kind {
            CREDIT_PRESENT_KIND_CASHU => {
                let encoded = std::str::from_utf8(payload)
                    .map_err(|_| ApiError::invalid_request("Cashu token is not UTF-8"))?
                    .trim();
                let summary = TokenSummary::parse(encoded)
                    .map_err(|e| ApiError::invalid_request(e.to_string()))?;
                if !state.config.accepts_mint(&summary.mint) {
                    return Err(ApiError::mint_not_accepted(format!(
                        "{} is not an accepted mint",
                        summary.mint
                    )));
                }
                if summary.unit != "sat" {
                    return Err(ApiError::wrong_amount(format!(
                        "token unit {} is not sat",
                        summary.unit
                    )));
                }
                let key_hex = hex::encode(token_key(&summary.secrets));
                match store.get(&key_hex) {
                    Some(TokenState::Issued { .. }) => {
                        return Err(ApiError::already_redeemed(
                            "this token already bought a session grant",
                        ));
                    }
                    Some(TokenState::Redeemed { server_id, .. }) => {
                        return Err(ApiError::already_redeemed(format!(
                            "this token was already redeemed through {server_id}"
                        )));
                    }
                    Some(TokenState::Credentialed { .. }) => {
                        return Err(ApiError::already_redeemed(
                            "this token already bought an ARC credential",
                        ));
                    }
                    Some(TokenState::X402Credentialed { .. }) => {
                        return Err(ApiError::already_redeemed(
                            "this key belongs to an x402 payment",
                        ));
                    }
                    Some(TokenState::Pending { .. }) => {
                        tracing::error!(token_key = %key_hex,
                            "token with an unknown earlier swap outcome presented again; reconcile manually");
                        return Err(ApiError::token_rejected(format!(
                            "an earlier attempt with this token has an unknown outcome (key {key_hex}); contact the operator"
                        )));
                    }
                    Some(TokenState::Failed { .. }) | None => {}
                }
                store
                    .record(&key_hex, TokenState::Pending { first_seen: now })
                    .map_err(|e| ApiError::internal(format!("store: {e}")))?;
                let received = match state.swapper.receive(&summary, encoded).await {
                    Ok(received) => received,
                    Err(SwapError::Rejected(message)) => {
                        store
                            .record(
                                &key_hex,
                                TokenState::Failed {
                                    at: now,
                                    reason: message.clone(),
                                },
                            )
                            .map_err(|e| ApiError::internal(format!("store: {e}")))?;
                        return Err(ApiError::token_rejected(message));
                    }
                    Err(SwapError::Unavailable(message)) => {
                        store
                            .record(
                                &key_hex,
                                TokenState::Failed {
                                    at: now,
                                    reason: message.clone(),
                                },
                            )
                            .map_err(|e| ApiError::internal(format!("store: {e}")))?;
                        return Err(ApiError::mint_unavailable(message));
                    }
                    Err(SwapError::Unknown(message)) => {
                        tracing::warn!(token_key = %key_hex, %message, "swap outcome unknown; keeping pending marker");
                        return Err(ApiError::mint_unavailable(message));
                    }
                };
                if received == 0 {
                    return Err(ApiError::token_rejected(
                        "the mint credited nothing for this token",
                    ));
                }
                store
                    .record(
                        &key_hex,
                        TokenState::Redeemed {
                            server_id: verified.server_id.clone(),
                            received,
                            mint: summary.mint.clone(),
                            unit: summary.unit.clone(),
                        },
                    )
                    .map_err(|e| ApiError::internal(format!("store: {e}")))?;
                gas_added = gas_added.saturating_add(gas.sats_to_gas(received));
                sat_value = sat_value.saturating_add(received);
                items_accepted += 1;
            }
            CREDIT_PRESENT_KIND_ARC => {
                let Some(arc) = state.arc.as_ref() else {
                    return Err(ApiError::unsupported_kind(
                        "this issuer does not issue ARC credentials",
                    ));
                };
                let (epoch, presentations) =
                    decode_presentations(payload).map_err(ApiError::invalid_request)?;
                if !arc.accepts(epoch, now) {
                    return Err(ApiError::expired_epoch(format!(
                        "ARC epoch {epoch} is not accepted (current {})",
                        arc.current_epoch(now)
                    )));
                }
                match consumed_epoch {
                    None => consumed_epoch = Some(epoch),
                    Some(previous) if previous != epoch => {
                        return Err(ApiError::invalid_request(
                            "one redeem request may carry presentations of one epoch only",
                        ));
                    }
                    Some(_) => {}
                }
                for presentation in presentations {
                    let tag = arc.verify(epoch, presentation)?;
                    if consumed_tags.contains(&tag) || redeem_store.has_tag(epoch, &tag) {
                        return Err(ApiError::double_spend(
                            "an ARC presentation in this request was already spent",
                        ));
                    }
                    consumed_tags.push(tag);
                    gas_added = gas_added.saturating_add(gas.gas_per_credit);
                    sat_value = sat_value.saturating_add(gas.credit_sat);
                }
                items_accepted += 1;
            }
            other => {
                return Err(ApiError::invalid_request(format!(
                    "unknown presentation kind {other}"
                )));
            }
        }
    }

    let preimage =
        RedeemResponseV1::signing_preimage(&verified.nonce, gas_added, sat_value, items_accepted);
    let issuer_signature_hex = hex::encode(state.issuer.sign(&preimage));
    let event = RedeemEvent {
        server_id: verified.server_id.clone(),
        nonce_hex: verified.nonce_hex.clone(),
        unix_time: now,
        gas_added,
        sat_value,
        items_accepted,
        issuer_signature_hex,
        epoch: consumed_epoch,
        tags_hex: consumed_tags,
    };
    let answer = event.response();
    redeem_store
        .record(event)
        .map_err(|e| ApiError::internal(format!("redeem store: {e}")))?;
    tracing::info!(server_id = %verified.server_id, gas_added, sat_value, items_accepted, "redeemed");
    Ok(Json(answer))
}

/// `POST /v2/credentials` (docs/CREDITS.md): pay one listed pack with a
/// Cashu token and receive a blind-issued ARC credential under the current
/// epoch. Idempotent per token: the same token with the same request
/// replays the stored response; with another request it is refused, so a
/// client must persist its request and secrets before sending.
async fn credentials(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    let value: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|e| ApiError::invalid_request(format!("body: {e}")))?;
    if value.get("token").is_some() {
        let request: CredentialRequestV2 = serde_json::from_value(value)
            .map_err(|e| ApiError::invalid_request(format!("body: {e}")))?;
        return credentials_cashu(state, request)
            .await
            .map(IntoResponse::into_response);
    }
    let request: X402CredentialRequest = serde_json::from_value(value)
        .map_err(|e| ApiError::invalid_request(format!("body: {e}")))?;
    credentials_x402(state, headers, body, request).await
}

/// The Cashu purchase: the body carried a `token`.
async fn credentials_cashu(
    state: Arc<AppState>,
    request: CredentialRequestV2,
) -> Result<Json<CredentialResponseV2>, ApiError> {
    let (Some(arc_config), Some(arc)) = (&state.config.arc, &state.arc) else {
        return Err(ApiError::unsupported_kind(
            "this issuer does not issue ARC credentials",
        ));
    };
    if request.credits != u64::from(arc.presentation_limit())
        || !arc_config
            .credential_offers
            .iter()
            .any(|offer| offer.credits == request.credits && offer.sat == request.sat)
    {
        return Err(ApiError::invalid_request("unknown credential offer"));
    }
    let request_bytes = hex::decode(&request.request_hex)
        .map_err(|_| ApiError::invalid_request("request_hex is not hex"))?;
    if request_bytes.len() != arc::CredentialRequest::SIZE {
        return Err(ApiError::invalid_request(format!(
            "request_hex must encode {} bytes",
            arc::CredentialRequest::SIZE
        )));
    }
    let request_hex = hex::encode(&request_bytes);
    let encoded = request.token.trim();
    let summary =
        TokenSummary::parse(encoded).map_err(|e| ApiError::invalid_request(e.to_string()))?;
    if !state.config.accepts_mint(&summary.mint) {
        return Err(ApiError::mint_not_accepted(format!(
            "{} is not an accepted mint",
            summary.mint
        )));
    }
    if summary.unit != "sat" || summary.amount != request.sat {
        return Err(ApiError::wrong_amount(format!(
            "token is worth {} {}, offer costs {} sat",
            summary.amount, summary.unit, request.sat
        )));
    }
    let key_hex = hex::encode(token_key(&summary.secrets));
    let now = (state.clock)();
    let epoch = arc.current_epoch(now);

    let mut store = state.store.lock().await;
    match store.get(&key_hex).cloned() {
        Some(TokenState::Credentialed {
            epoch,
            request_hex: stored_request,
            response_hex,
            ..
        }) => {
            if stored_request != request_hex {
                return Err(ApiError::invalid_request(
                    "this token already bought a credential for another request; the original stands",
                ));
            }
            tracing::info!(epoch, "replaying a credential for a token seen before");
            return Ok(Json(CredentialResponseV2 {
                response_hex,
                epoch,
                presentation_limit: arc.presentation_limit(),
                issuer_public_key_hex: arc.public_key_hex(epoch),
                valid_until: arc.valid_until(epoch),
            }));
        }
        Some(TokenState::Issued { .. }) => {
            return Err(ApiError::already_redeemed(
                "this token already bought a session grant",
            ));
        }
        Some(TokenState::Redeemed { server_id, .. }) => {
            return Err(ApiError::already_redeemed(format!(
                "this token was already redeemed through {server_id}"
            )));
        }
        Some(TokenState::X402Credentialed { .. }) => {
            return Err(ApiError::already_redeemed(
                "this key belongs to an x402 payment",
            ));
        }
        Some(TokenState::Pending { .. }) => {
            tracing::error!(token_key = %key_hex,
                "token with an unknown earlier swap outcome presented again; reconcile manually");
            return Err(ApiError::token_rejected(format!(
                "an earlier attempt with this token has an unknown outcome (key {key_hex}); contact the operator"
            )));
        }
        Some(TokenState::Failed { .. }) | None => {}
    }
    store
        .record(&key_hex, TokenState::Pending { first_seen: now })
        .map_err(|e| ApiError::internal(format!("store: {e}")))?;
    let received = match state.swapper.receive(&summary, encoded).await {
        Ok(received) => received,
        Err(SwapError::Rejected(message)) => {
            store
                .record(
                    &key_hex,
                    TokenState::Failed {
                        at: now,
                        reason: message.clone(),
                    },
                )
                .map_err(|e| ApiError::internal(format!("store: {e}")))?;
            return Err(ApiError::token_rejected(message));
        }
        Err(SwapError::Unavailable(message)) => {
            store
                .record(
                    &key_hex,
                    TokenState::Failed {
                        at: now,
                        reason: message.clone(),
                    },
                )
                .map_err(|e| ApiError::internal(format!("store: {e}")))?;
            return Err(ApiError::mint_unavailable(message));
        }
        Err(SwapError::Unknown(message)) => {
            tracing::warn!(token_key = %key_hex, %message, "swap outcome unknown; keeping pending marker");
            return Err(ApiError::mint_unavailable(message));
        }
    };
    if received < request.sat {
        tracing::warn!(token_key = %key_hex, received, face = request.sat, "mint credited less than face value (input fees)");
    }
    let response_bytes = arc.issue(epoch, &request_bytes)?;
    let response_hex = hex::encode(&response_bytes);
    store
        .record(
            &key_hex,
            TokenState::Credentialed {
                epoch,
                request_hex,
                response_hex: response_hex.clone(),
                received,
                mint: summary.mint.clone(),
                unit: summary.unit.clone(),
            },
        )
        .map_err(|e| ApiError::internal(format!("store: {e}")))?;
    tracing::info!(epoch, received, mint = %summary.mint, "ARC credential issued");
    Ok(Json(CredentialResponseV2 {
        response_hex,
        epoch,
        presentation_limit: arc.presentation_limit(),
        issuer_public_key_hex: arc.public_key_hex(epoch),
        valid_until: arc.valid_until(epoch),
    }))
}

/// `POST /v2/credentials` body without a Cashu token: an x402 purchase of
/// one pack. The blinded ARC request travels in the same body on the
/// challenge and on the paid retry; the body bytes are part of the request
/// binding, so the retry must repeat them exactly.
#[derive(Deserialize)]
struct X402CredentialRequest {
    credits: u64,
    sat: u64,
    request_hex: String,
}

/// x402 `exact/lnbtc` (`crate::x402`): without `PAYMENT-SIGNATURE`, answer
/// `402` with a fresh request-bound invoice; with it, settle the proof and
/// issue the credential. One payment buys one credential: a repeat of the
/// identical request replays the stored answer, another request with the
/// same payment is `duplicate_settlement`.
async fn credentials_x402(
    state: Arc<AppState>,
    headers: HeaderMap,
    body: Bytes,
    request: X402CredentialRequest,
) -> Result<Response, ApiError> {
    let Some(x) = state.x402.as_ref() else {
        return Err(ApiError::unsupported_kind(
            "the body has no Cashu token and x402 is not enabled on this issuer",
        ));
    };
    let (Some(arc_config), Some(arc)) = (&state.config.arc, &state.arc) else {
        return Err(ApiError::unsupported_kind(
            "this issuer does not issue ARC credentials",
        ));
    };
    if request.credits != u64::from(arc.presentation_limit())
        || !arc_config
            .credential_offers
            .iter()
            .any(|offer| offer.credits == request.credits && offer.sat == request.sat)
    {
        return Err(ApiError::invalid_request("unknown credential offer"));
    }
    let request_bytes = hex::decode(&request.request_hex)
        .map_err(|_| ApiError::invalid_request("request_hex is not hex"))?;
    if request_bytes.len() != arc::CredentialRequest::SIZE {
        return Err(ApiError::invalid_request(format!(
            "request_hex must encode {} bytes",
            arc::CredentialRequest::SIZE
        )));
    }
    let request_hex = hex::encode(&request_bytes);
    let bound = x.bind(&headers, &body).map_err(ApiError::invalid_request)?;
    let now = (state.clock)();

    let Some(signature) = headers.get(&PAYMENT_SIGNATURE) else {
        let ip = client_ip(&headers);
        let required = match x
            .challenge(&bound, request.credits, request.sat, now, &ip)
            .await
        {
            Ok(required) => required,
            Err(ChallengeError::RateLimited) => {
                return Err(ApiError::rate_limited(
                    "too many fresh invoices from this address; retry in a minute",
                ));
            }
            Err(ChallengeError::Receiver(e)) => {
                tracing::warn!(error = %e, "x402: receiver unavailable");
                return Err(ApiError::receiver_unavailable(
                    "the Lightning receiver is unavailable; retry later",
                ));
            }
            Err(ChallengeError::Invalid(reason)) => {
                tracing::error!(
                    reason,
                    "x402: the receiver's invoice fails our own checks; check x402.node_pubkey_hex"
                );
                return Err(ApiError::internal("receiver invoice rejected"));
            }
        };
        return Ok((
            StatusCode::PAYMENT_REQUIRED,
            [(PAYMENT_REQUIRED, header_value(&required))],
            Json(required),
        )
            .into_response());
    };
    let signature = signature
        .to_str()
        .map_err(|_| ApiError::invalid_request("PAYMENT-SIGNATURE is not ASCII"))?;
    let payload: PaymentPayload = parse_header(signature)
        .map_err(|e| ApiError::invalid_request(format!("PAYMENT-SIGNATURE: {e}")))?;
    let network = x.network.caip2();
    let settled = match x.settle(&bound, request.sat, &payload, now) {
        Ok(settled) => settled,
        Err(reason) => {
            tracing::info!(reason, "x402: settlement refused");
            return Ok(payment_failed(network, reason));
        }
    };
    let epoch = arc.current_epoch(now);
    let key = format!("x402:{}", settled.replay_key);
    let mut store = state.store.lock().await;
    match store.get(&key).cloned() {
        Some(TokenState::X402Credentialed {
            request_hex: stored_request,
            response_hex,
            epoch,
            ..
        }) => {
            if stored_request != request_hex {
                return Ok(payment_failed(network, "duplicate_settlement"));
            }
            tracing::info!(
                epoch,
                "x402: replaying a credential for a payment seen before"
            );
            return Ok(credential_response(arc, epoch, response_hex, &settled));
        }
        Some(_) => return Ok(payment_failed(network, "duplicate_settlement")),
        None => {}
    }
    let response_bytes = arc.issue(epoch, &request_bytes)?;
    let response_hex = hex::encode(&response_bytes);
    store
        .record(
            &key,
            TokenState::X402Credentialed {
                network: network.to_owned(),
                payment_hash_hex: settled.payment_hash_hex.clone(),
                msat: settled.amount_msat,
                epoch,
                request_hex,
                response_hex: response_hex.clone(),
            },
        )
        .map_err(|e| ApiError::internal(format!("store: {e}")))?;
    tracing::info!(
        epoch,
        msat = settled.amount_msat,
        payment_hash = %settled.payment_hash_hex,
        "x402: ARC credential issued"
    );
    Ok(credential_response(arc, epoch, response_hex, &settled))
}

fn credential_response(
    arc: &ArcIssuer,
    epoch: u32,
    response_hex: String,
    settled: &Settled,
) -> Response {
    let settlement = SettlementResponse {
        success: true,
        error_reason: None,
        transaction: settled.payment_hash_hex.clone(),
        network: settled.network.caip2().to_owned(),
    };
    (
        StatusCode::OK,
        [(PAYMENT_RESPONSE, header_value(&settlement))],
        Json(CredentialResponseV2 {
            response_hex,
            epoch,
            presentation_limit: arc.presentation_limit(),
            issuer_public_key_hex: arc.public_key_hex(epoch),
            valid_until: arc.valid_until(epoch),
        }),
    )
        .into_response()
}

/// A refused settlement: `402` with the facilitator's reason in
/// `PAYMENT-RESPONSE` (no new invoice; the client asks again without a
/// signature for a fresh challenge).
fn payment_failed(network: &str, reason: &str) -> Response {
    let settlement = SettlementResponse::failure(network, reason);
    (
        StatusCode::PAYMENT_REQUIRED,
        [(PAYMENT_RESPONSE, header_value(&settlement))],
        Json(serde_json::json!({ "error": "payment_failed", "message": reason })),
    )
        .into_response()
}

/// The client address for the invoice limiter: the tunnel's
/// `CF-Connecting-IP`, else the first `X-Forwarded-For` hop, else one shared
/// bucket.
fn client_ip(headers: &HeaderMap) -> String {
    headers
        .get("cf-connecting-ip")
        .and_then(|v| v.to_str().ok())
        .or_else(|| {
            headers
                .get("x-forwarded-for")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.split(',').next())
        })
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("local")
        .to_owned()
}

/// `GET /v2/x402/invoices/{payment_hash}`: the state of one challenge
/// invoice, so a browser whose user paid the QR code from a phone can finish
/// the same x402 retry; the preimage is returned once the node reports the
/// invoice paid. Only invoices carrying the x402 label prefix are visible.
async fn x402_invoice_status(
    State(state): State<Arc<AppState>>,
    Path(payment_hash): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let Some(x) = state.x402.as_ref() else {
        return Err(ApiError::unsupported_kind(
            "x402 is not enabled on this issuer",
        ));
    };
    if !x402::is_lower_hex(&payment_hash, 64) {
        return Err(ApiError::invalid_request(
            "payment_hash must be 64 lowercase hex characters",
        ));
    }
    let found = x.receiver.lookup(&payment_hash).await.map_err(|e| {
        tracing::warn!(error = %e, "x402: invoice lookup failed");
        ApiError::receiver_unavailable("the Lightning receiver is unavailable; retry later")
    })?;
    let Some(invoice) = found.filter(|i| i.label.starts_with(&x.config.label_prefix)) else {
        return Err(ApiError::not_found(
            "no x402 invoice with this payment hash",
        ));
    };
    let preimage = if invoice.status == "paid" {
        invoice.preimage_hex
    } else {
        None
    };
    Ok(Json(serde_json::json!({
        "payment_hash": payment_hash,
        "status": invoice.status,
        "bolt11": invoice.bolt11,
        "preimage": preimage,
    })))
}
