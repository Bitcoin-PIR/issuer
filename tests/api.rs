//! HTTP contract tests with a fake mint. Nothing here touches the network.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use bpir_issuer::api::{build_router, AppState};
use bpir_issuer::cashu::{token_key, SwapError, Swapper, TokenSummary};
use bpir_issuer::config::Config;
use bpir_issuer::ecash::{EcashSeller, SaleKeyset, SellError};
use bpir_issuer::issuer_key::IssuerKey;
use bpir_issuer::redeem::RedeemStore;
use bpir_issuer::store::{IssuedGrant, State as TokenState, Store};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use http_body_util::BodyExt;
use pir_credit::issuer::{RedeemItemV1, RedeemRequestV1, RedeemResponseV1, REDEEM_NONCE_LEN};
use pir_identity::{sign_identity_cert, IdentityCert};
use tokio::sync::Mutex;
use tower::ServiceExt;

const MINT: &str = "https://mint.example";

/// Scripted mint: answers per call from a queue, records every token it saw.
struct FakeSwapper {
    script: StdMutex<Vec<Result<u64, SwapError>>>,
    seen: StdMutex<Vec<String>>,
}

impl FakeSwapper {
    fn new(script: Vec<Result<u64, SwapError>>) -> Self {
        Self {
            script: StdMutex::new(script),
            seen: StdMutex::new(Vec::new()),
        }
    }
}

#[async_trait::async_trait]
impl Swapper for FakeSwapper {
    async fn receive(&self, _summary: &TokenSummary, encoded: &str) -> Result<u64, SwapError> {
        self.seen.lock().unwrap().push(encoded.to_string());
        let mut script = self.script.lock().unwrap();
        if script.is_empty() {
            panic!("fake mint called more often than scripted");
        }
        script.remove(0)
    }
}

/// Ecash sales are not exercised here (`tests/x402.rs` covers them).
struct NoSeller;

#[async_trait::async_trait]
impl EcashSeller for NoSeller {
    async fn keyset(&self) -> Result<SaleKeyset, SellError> {
        Err(SellError::Unavailable("no mint in this test".into()))
    }
    async fn spendable(&self) -> Result<u64, SellError> {
        Err(SellError::Unavailable("no mint in this test".into()))
    }
    async fn sell(
        &self,
        _: &str,
        _: u64,
        _: &[cdk::nuts::BlindedMessage],
    ) -> Result<Vec<cdk::nuts::BlindSignature>, SellError> {
        Err(SellError::Unavailable("no mint in this test".into()))
    }
    async fn restore(
        &self,
        _: &str,
        _: &[cdk::nuts::BlindedMessage],
    ) -> Result<Option<Vec<cdk::nuts::BlindSignature>>, SellError> {
        Err(SellError::Unavailable("no mint in this test".into()))
    }
}

struct Harness {
    app: axum::Router,
    state: Arc<AppState>,
    _dir: tempfile::TempDir,
}

fn config(dir: &std::path::Path) -> Config {
    toml::from_str(&format!(
        r#"
        listen = "127.0.0.1:0"
        grant_key_path = "{0}/grant.key"
        wallet_seed_path = "{0}/wallet.seed"
        wallet_db_path = "{0}/wallet.sqlite"
        store_path = "{0}/grants.jsonl"
        mints = ["{MINT}"]
        cors_origins = ["https://www.bitcoinpir.org"]
        "#,
        dir.display()
    ))
    .unwrap()
}

static CLOCK: AtomicU64 = AtomicU64::new(1_800_000_000);

fn harness(script: Vec<Result<u64, SwapError>>) -> Harness {
    let dir = tempfile::tempdir().unwrap();
    harness_in(dir, script)
}

fn harness_in(dir: tempfile::TempDir, script: Vec<Result<u64, SwapError>>) -> Harness {
    let config = config(dir.path());
    let store = Store::open(&config.store_path).unwrap();
    let redeem_store = RedeemStore::open(&config.redeem_store_path()).unwrap();
    let state = Arc::new(AppState {
        config,
        issuer: IssuerKey::new(&[5u8; 32]),
        swapper: Box::new(FakeSwapper::new(script)),
        seller: Box::new(NoSeller),
        store: Mutex::new(store),
        redeem_store: Mutex::new(redeem_store),
        operator_keys: vec![operator_key().verifying_key()],
        x402: None,
        clock: Box::new(|| CLOCK.load(Ordering::SeqCst)),
    });
    Harness {
        app: build_router(Arc::clone(&state)),
        state,
        _dir: dir,
    }
}

fn fake_token(amounts: &[u64]) -> String {
    bpir_issuer_test_token(MINT, "sat", amounts)
}

/// Same construction as `cashu::test_support::fake_token` (that helper is
/// `cfg(test)` inside the crate, so integration tests rebuild it here).
fn bpir_issuer_test_token(mint: &str, unit: &str, amounts: &[u64]) -> String {
    use cdk::mint_url::MintUrl;
    use cdk::nuts::{CurrencyUnit, Id, Proof, PublicKey, Token};
    use cdk::secret::Secret;
    use cdk::Amount;
    use std::str::FromStr;
    let keyset = Id::from_str("00ffd48b8f5ecf80").unwrap();
    let c =
        PublicKey::from_hex("02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2")
            .unwrap();
    let proofs: Vec<Proof> = amounts
        .iter()
        .map(|a| Proof::new(Amount::from(*a), keyset, Secret::generate(), c))
        .collect();
    Token::new(
        MintUrl::from_str(mint).unwrap(),
        proofs,
        None,
        CurrencyUnit::from_str(unit).unwrap(),
    )
    .to_string()
}

fn operator_key() -> SigningKey {
    SigningKey::from_bytes(&[21u8; 32])
}

fn server_key() -> SigningKey {
    SigningKey::from_bytes(&[22u8; 32])
}

fn server_cert(operator: &SigningKey, server_id: &str) -> IdentityCert {
    sign_identity_cert(
        operator,
        server_id,
        server_key().verifying_key().to_bytes(),
        0,
        0,
    )
}

fn redeem_request(
    cert: &IdentityCert,
    server_id: &str,
    nonce: [u8; REDEEM_NONCE_LEN],
    items: &[(u8, Vec<u8>)],
) -> String {
    let unix_time = CLOCK.load(Ordering::SeqCst);
    let borrowed: Vec<(u8, &[u8])> = items.iter().map(|(k, p)| (*k, p.as_slice())).collect();
    let preimage = RedeemRequestV1::signing_preimage(server_id, &nonce, unix_time, &borrowed);
    serde_json::to_string(&RedeemRequestV1 {
        server_id: server_id.to_owned(),
        identity_cert_hex: hex::encode(cert.encode()),
        nonce_hex: hex::encode(nonce),
        unix_time,
        items: items
            .iter()
            .map(|(kind, payload)| RedeemItemV1 {
                kind: *kind,
                payload_hex: hex::encode(payload),
            })
            .collect(),
        signature_hex: hex::encode(server_key().sign(&preimage).to_bytes()),
    })
    .unwrap()
}

async fn post_redeem(app: &axum::Router, body: String) -> (StatusCode, serde_json::Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v2/redeem")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

#[tokio::test]
async fn info_v2_publishes_gas_parameters_mints_and_the_rate_card() {
    let h = harness(vec![]);
    let response = h
        .app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v2/info")
                .header(header::ORIGIN, "https://www.bitcoinpir.org")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .unwrap(),
        "https://www.bitcoinpir.org"
    );
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["service"], "bitcoinpir-issuer");
    assert_eq!(v["version"], 2);
    assert_eq!(v["credit_sat"], 10);
    assert_eq!(v["gas_per_credit"], 72_000);
    assert_eq!(v["base_gas_per_frame"], 20);
    assert_eq!(v["egress_gas_per_mb"], 1_000);
    assert_eq!(v["mints"], serde_json::json!([MINT]));
    // Nothing to buy up front: Cashu ecash is presented directly.
    assert_eq!(v["offers"], serde_json::json!([]));
    assert!(v.get("arc").is_none(), "{v}");
    assert_eq!(
        v["rate_card"][0],
        serde_json::json!({"flow": "onion_single_address", "credits": 10})
    );
    assert_eq!(v["rate_card"].as_array().unwrap().len(), 4);
}

#[tokio::test]
async fn redeem_settles_a_cashu_token_and_replays_the_signed_answer() {
    let h = harness(vec![Ok(200)]);
    let cert = server_cert(&operator_key(), "pir1");
    let token = fake_token(&[128, 64, 8]);
    let nonce = [0x33u8; REDEEM_NONCE_LEN];
    let body = redeem_request(&cert, "pir1", nonce, &[(1, token.as_bytes().to_vec())]);
    let (status, answer) = post_redeem(&h.app, body.clone()).await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    // 200 sat received at 72,000 gas per 10 sat.
    assert_eq!(answer["gas_added"], 1_440_000);
    assert_eq!(answer["sat_value"], 200);
    assert_eq!(answer["items_accepted"], 1);
    let parsed: RedeemResponseV1 = serde_json::from_value(answer.clone()).unwrap();
    let preimage = RedeemResponseV1::signing_preimage(&nonce, 1_440_000, 200, 1);
    let signature =
        Signature::from_slice(&hex::decode(&parsed.issuer_signature_hex).unwrap()).unwrap();
    VerifyingKey::from_bytes(&h.state.issuer.public_key())
        .unwrap()
        .verify(&preimage, &signature)
        .unwrap();

    // Same nonce again: the stored answer, byte for byte, and no mint call
    // (the fake mint's script is empty now and would panic).
    let (status2, answer2) = post_redeem(&h.app, body).await;
    assert_eq!(status2, StatusCode::OK);
    assert_eq!(answer2, answer);

    // The token is booked to pir1 and the ledger knows it.
    let summary = TokenSummary::parse(&token).unwrap();
    let key_hex = hex::encode(token_key(&summary.secrets));
    assert!(matches!(
        h.state.store.lock().await.get(&key_hex),
        Some(TokenState::Redeemed { server_id, received: 200, .. }) if server_id == "pir1"
    ));
    let redeem_store = h.state.redeem_store.lock().await;
    let totals = &redeem_store.totals()["pir1"];
    assert_eq!(
        (totals.redemptions, totals.gas, totals.sat),
        (1, 1_440_000, 200)
    );
}

#[tokio::test]
async fn redeem_refuses_foreign_servers_reused_tokens_and_unsupported_kinds() {
    let h = harness(vec![Err(SwapError::Rejected("already spent".into()))]);
    let cert = server_cert(&operator_key(), "pir1");
    let token = fake_token(&[128, 64, 16, 2]);

    // A certificate from an operator this issuer does not serve.
    let foreign_cert = server_cert(&SigningKey::from_bytes(&[23u8; 32]), "pir1");
    let body = redeem_request(
        &foreign_cert,
        "pir1",
        [1u8; 16],
        &[(1, token.as_bytes().to_vec())],
    );
    let (status, answer) = post_redeem(&h.app, body).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{answer}");
    assert_eq!(answer["error"], "unauthorized");

    // A token that bought a (now retired) session grant cannot be redeemed
    // as credits: old store lines replay as spent tokens.
    let summary = TokenSummary::parse(&token).unwrap();
    h.state
        .store
        .lock()
        .await
        .record(
            &hex::encode(token_key(&summary.secrets)),
            TokenState::Issued {
                grant: IssuedGrant {
                    grant_base64: "AAAA".into(),
                    grant_id_hex: "00".repeat(16),
                    credits: 1000,
                    issued_at: 1,
                    expires_at: 2,
                },
                received: 210,
                mint: MINT.into(),
                unit: "sat".into(),
            },
        )
        .unwrap();
    let body = redeem_request(&cert, "pir1", [2u8; 16], &[(1, token.as_bytes().to_vec())]);
    let (status, answer) = post_redeem(&h.app, body).await;
    assert_eq!(status, StatusCode::PAYMENT_REQUIRED, "{answer}");
    assert_eq!(answer["error"], "already_redeemed");

    // The mint rejects a fresh token: 402, nothing booked.
    let rejected = fake_token(&[4]);
    let body = redeem_request(
        &cert,
        "pir1",
        [3u8; 16],
        &[(1, rejected.as_bytes().to_vec())],
    );
    let (status, answer) = post_redeem(&h.app, body).await;
    assert_eq!(status, StatusCode::PAYMENT_REQUIRED, "{answer}");
    assert_eq!(answer["error"], "token_rejected");
    assert!(h.state.redeem_store.lock().await.totals().is_empty());

    // A presentation kind the contract does not define.
    let body = redeem_request(&cert, "pir1", [4u8; 16], &[(3, vec![9, 9, 9])]);
    let (status, answer) = post_redeem(&h.app, body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{answer}");
    assert_eq!(answer["error"], "invalid_request");

    // A token from a mint the issuer does not accept.
    let other_mint = bpir_issuer_test_token("https://other.example", "sat", &[8]);
    let body = redeem_request(
        &cert,
        "pir1",
        [5u8; 16],
        &[(1, other_mint.as_bytes().to_vec())],
    );
    let (status, answer) = post_redeem(&h.app, body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{answer}");
    assert_eq!(answer["error"], "mint_not_accepted");

    // A stale request clock.
    let stale = {
        let nonce = [6u8; 16];
        let unix_time = CLOCK.load(Ordering::SeqCst) - 3600;
        let payload = token.as_bytes().to_vec();
        let preimage =
            RedeemRequestV1::signing_preimage("pir1", &nonce, unix_time, &[(1, &payload)]);
        serde_json::to_string(&RedeemRequestV1 {
            server_id: "pir1".into(),
            identity_cert_hex: hex::encode(cert.encode()),
            nonce_hex: hex::encode(nonce),
            unix_time,
            items: vec![RedeemItemV1 {
                kind: 1,
                payload_hex: hex::encode(&payload),
            }],
            signature_hex: hex::encode(server_key().sign(&preimage).to_bytes()),
        })
        .unwrap()
    };
    let (status, answer) = post_redeem(&h.app, stale).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{answer}");
    assert_eq!(answer["error"], "invalid_request");
}

#[tokio::test]
async fn redeem_refuses_retired_arc_presentations() {
    // The fake mint is not scripted: nothing may reach it.
    let h = harness(vec![]);
    let cert = server_cert(&operator_key(), "pir1");
    let body = redeem_request(&cert, "pir1", [0x44u8; 16], &[(2, vec![1, 2, 3])]);
    let (status, answer) = post_redeem(&h.app, body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{answer}");
    assert_eq!(answer["error"], "unsupported_kind");
    assert_eq!(
        answer["message"],
        "ARC credentials are retired; present Cashu ecash (kind 1)"
    );
    assert!(h.state.redeem_store.lock().await.totals().is_empty());
}

#[tokio::test]
async fn arc_era_store_lines_replay_and_their_tokens_stay_spent() {
    // grants.jsonl as the ARC-era release wrote it: a token that bought an
    // ARC credential, and an x402 payment that bought one.
    let dir = tempfile::tempdir().unwrap();
    let token = fake_token(&[32, 8]);
    let key_hex = hex::encode(token_key(&TokenSummary::parse(&token).unwrap().secrets));
    let network = "lnbtc:000000000019d6689c085ae165831e93";
    let payment_hash = "ab".repeat(32);
    let payment_key = format!("x402:{network}:{payment_hash}");
    std::fs::write(
        dir.path().join("grants.jsonl"),
        format!(
            "{{\"token_key_hex\":\"{key_hex}\",\"state\":\"pending\",\"first_seen\":1799999000}}\n\
             {{\"token_key_hex\":\"{key_hex}\",\"state\":\"credentialed\",\"epoch\":231,\"request_hex\":\"01\",\"response_hex\":\"02\",\"received\":40,\"mint\":\"{MINT}\",\"unit\":\"sat\"}}\n\
             {{\"token_key_hex\":\"{payment_key}\",\"state\":\"x402_credentialed\",\"network\":\"{network}\",\"payment_hash_hex\":\"{payment_hash}\",\"msat\":40000,\"epoch\":231,\"request_hex\":\"03\",\"response_hex\":\"04\"}}\n"
        ),
    )
    .unwrap();
    // The fake mint is not scripted: the spent token must not reach it.
    let h = harness_in(dir, vec![]);
    {
        let store = h.state.store.lock().await;
        assert!(matches!(
            store.get(&key_hex),
            Some(TokenState::Credentialed {
                epoch: 231,
                received: 40,
                ..
            })
        ));
        assert!(matches!(
            store.get(&payment_key),
            Some(TokenState::X402Credentialed { msat: 40_000, .. })
        ));
        assert!(store.pending_keys().is_empty());
    }
    let cert = server_cert(&operator_key(), "pir1");
    let body = redeem_request(
        &cert,
        "pir1",
        [0x55u8; 16],
        &[(1, token.as_bytes().to_vec())],
    );
    let (status, answer) = post_redeem(&h.app, body).await;
    assert_eq!(status, StatusCode::PAYMENT_REQUIRED, "{answer}");
    assert_eq!(answer["error"], "already_redeemed");
}
