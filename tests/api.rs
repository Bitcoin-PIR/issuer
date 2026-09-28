//! HTTP contract tests with a fake mint. Nothing here touches the network.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};

use arc::{
    create_credential_request, finalize_credential, make_presentation_state, present,
    CredentialResponse, ServerPublicKey,
};
use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use bpir_issuer::api::{build_router, AppState};
use bpir_issuer::arc::ArcIssuer;
use bpir_issuer::cashu::{token_key, SwapError, Swapper, TokenSummary};
use bpir_issuer::config::Config;
use bpir_issuer::issuer_key::IssuerKey;
use bpir_issuer::redeem::RedeemStore;
use bpir_issuer::store::{IssuedGrant, State as TokenState, Store};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use http_body_util::BodyExt;
use pir_credit::arc::{encode_presentations, epoch_at, presentation_context, request_context};
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
        [arc]
        seed_path = "{0}/arc.seed"
        presentation_limit = 4
        [[arc.credential_offers]]
        credits = 4
        sat = 40
        "#,
        dir.display()
    ))
    .unwrap()
}

static CLOCK: AtomicU64 = AtomicU64::new(1_800_000_000);
const ARC_EPOCH: u64 = 90 * 86_400;
const ARC_GRACE: u64 = 30 * 86_400;

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
        store: Mutex::new(store),
        redeem_store: Mutex::new(redeem_store),
        operator_keys: vec![operator_key().verifying_key()],
        arc: Some(ArcIssuer::new([9u8; 32], ARC_EPOCH, ARC_GRACE, 4)),
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
async fn info_v2_publishes_gas_parameters_sat_offers_and_the_rate_card() {
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
    assert_eq!(v["offers"], serde_json::json!([{"credits": 4, "sat": 40}]));
    let epoch = epoch_at(CLOCK.load(Ordering::SeqCst), ARC_EPOCH);
    assert_eq!(v["arc"]["epoch"], epoch);
    assert_eq!(v["arc"]["presentation_limit"], 4);
    assert_eq!(
        v["arc"]["issuer_public_key_hex"],
        h.state.arc.as_ref().unwrap().public_key_hex(epoch)
    );
    assert_eq!(
        v["arc"]["presentation_context_hex"],
        hex::encode(presentation_context(epoch))
    );
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

    // A kind-2 payload that is not even a payload.
    let body = redeem_request(&cert, "pir1", [4u8; 16], &[(2, vec![9, 9, 9])]);
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

async fn post_json(
    app: &axum::Router,
    path: &str,
    body: String,
) -> (StatusCode, serde_json::Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(path)
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
async fn credentials_are_blind_issued_and_their_presentations_redeem_exactly_once() {
    let h = harness(vec![Ok(40)]);
    let now = CLOCK.load(Ordering::SeqCst);
    let epoch = epoch_at(now, ARC_EPOCH);
    let issuer = h.state.arc.as_ref().unwrap();

    // Buy: a blinded request plus a token worth the pack.
    let (secrets, request) =
        create_credential_request(&request_context(epoch), &mut rand_core::OsRng).unwrap();
    let token = fake_token(&[32, 8]);
    let buy = serde_json::json!({
        "credits": 4, "sat": 40, "token": token, "request_hex": hex::encode(request.to_bytes())
    })
    .to_string();
    let (status, issued) = post_json(&h.app, "/v2/credentials", buy.clone()).await;
    assert_eq!(status, StatusCode::OK, "{issued}");
    assert_eq!(issued["epoch"], epoch);
    assert_eq!(issued["presentation_limit"], 4);
    assert_eq!(
        issued["issuer_public_key_hex"],
        issuer.public_key_hex(epoch)
    );
    // The same token and request replay the same response without a swap
    // (the fake mint's script is empty and would panic).
    let (status2, issued2) = post_json(&h.app, "/v2/credentials", buy).await;
    assert_eq!(status2, StatusCode::OK);
    assert_eq!(issued2, issued);
    // The same token with another request is refused.
    let (_, other_request) =
        create_credential_request(&request_context(epoch), &mut rand_core::OsRng).unwrap();
    let other = serde_json::json!({
        "credits": 4, "sat": 40, "token": token, "request_hex": hex::encode(other_request.to_bytes())
    })
    .to_string();
    let (status3, answer3) = post_json(&h.app, "/v2/credentials", other).await;
    assert_eq!(status3, StatusCode::BAD_REQUEST, "{answer3}");
    // An unknown pack.
    let wrong = serde_json::json!({
        "credits": 5, "sat": 40, "token": fake_token(&[32, 8]), "request_hex": hex::encode(request.to_bytes())
    })
    .to_string();
    let (status4, _) = post_json(&h.app, "/v2/credentials", wrong).await;
    assert_eq!(status4, StatusCode::BAD_REQUEST);

    // Finish the credential client-side and present three times.
    let pk = ServerPublicKey::from_bytes(
        &hex::decode(issued["issuer_public_key_hex"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    let response = CredentialResponse::from_bytes(
        &hex::decode(issued["response_hex"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    let credential = finalize_credential(&secrets, &pk, &request, &response).unwrap();
    let mut state = make_presentation_state(credential, &presentation_context(epoch), 4);
    let mut presentations = Vec::new();
    for _ in 0..3 {
        let (next, _nonce, presentation) = present(&state, &mut rand_core::OsRng).unwrap();
        state = next;
        presentations.push(presentation.to_bytes());
    }
    let payload = encode_presentations(epoch, &presentations).unwrap();
    let cert = server_cert(&operator_key(), "pir1");
    let body = redeem_request(&cert, "pir1", [0x44u8; 16], &[(2, payload.clone())]);
    let (status, answer) = post_redeem(&h.app, body).await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert_eq!(answer["gas_added"], 3 * 72_000);
    assert_eq!(answer["sat_value"], 30);
    assert_eq!(answer["items_accepted"], 1);

    // Spending the same presentations again, under a new nonce, is a double spend.
    let body = redeem_request(&cert, "pir1", [0x45u8; 16], &[(2, payload)]);
    let (status, answer) = post_redeem(&h.app, body).await;
    assert_eq!(status, StatusCode::PAYMENT_REQUIRED, "{answer}");
    assert_eq!(answer["error"], "double_spend");

    // The fourth and last presentation spends on its own; a fifth cannot be made.
    let (next, _nonce, last) = present(&state, &mut rand_core::OsRng).unwrap();
    state = next;
    assert!(matches!(
        present(&state, &mut rand_core::OsRng),
        Err(arc::Error::LimitExceeded)
    ));
    let payload = encode_presentations(epoch, &[last.to_bytes()]).unwrap();
    let body = redeem_request(&cert, "pir1", [0x46u8; 16], &[(2, payload)]);
    let (status, answer) = post_redeem(&h.app, body).await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert_eq!(answer["gas_added"], 72_000);

    // A payload claiming an epoch the issuer does not accept.
    let stale = encode_presentations(epoch + 5, &[presentations[0].clone()]).unwrap();
    let body = redeem_request(&cert, "pir1", [0x47u8; 16], &[(2, stale)]);
    let (status, answer) = post_redeem(&h.app, body).await;
    assert_eq!(status, StatusCode::PAYMENT_REQUIRED, "{answer}");
    assert_eq!(answer["error"], "expired_epoch");

    // The ledger booked four presentations to pir1.
    let totals = h.state.redeem_store.lock().await.totals()["pir1"].clone();
    assert_eq!(
        (totals.redemptions, totals.gas, totals.sat),
        (2, 4 * 72_000, 40)
    );
}
