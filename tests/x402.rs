//! x402 `exact/lnbtc` over the HTTP layer with a fake receiver that signs
//! invoices with secp256k1 key 1 (`payTo` 0279be…), the specification's
//! test key. Nothing here touches a node or the network.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use arc::create_credential_request;
use async_trait::async_trait;
use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use bpir_issuer::api::{build_router, AppState};
use bpir_issuer::arc::ArcIssuer;
use bpir_issuer::cashu::{SwapError, Swapper, TokenSummary};
use bpir_issuer::config::Config;
use bpir_issuer::issuer_key::IssuerKey;
use bpir_issuer::redeem::RedeemStore;
use bpir_issuer::store::Store;
use bpir_issuer::x402::binding::{http1, BoundHeader};
use bpir_issuer::x402::receiver::{CreatedInvoice, InvoiceSource, InvoiceState, ReceiverError};
use bpir_issuer::x402::server::X402State;
use bpir_issuer::x402::{
    header_value, parse_header, PaymentPayload, PaymentRequired, SettlementResponse,
};
use http_body_util::BodyExt;
use lightning_invoice::{Bolt11Invoice, Currency, InvoiceBuilder, PaymentSecret};
use pir_credit::arc::{epoch_at, request_context};
use serde_json::{json, Value};
use tokio::sync::Mutex;
use tower::ServiceExt;

const KEY_ONE_PUBKEY: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const PUBLIC_URL: &str = "https://issuer.example";
static CLOCK: AtomicU64 = AtomicU64::new(1_800_000_000);
const ARC_EPOCH: u64 = 90 * 86_400;
const ARC_GRACE: u64 = 30 * 86_400;

fn sign_invoice(description: &str, amount_msat: u64, expiry: u64, preimage: &[u8; 32]) -> String {
    let secp = Secp256k1::new();
    let mut key = [0u8; 32];
    key[31] = 1;
    let sk = SecretKey::from_slice(&key).unwrap();
    InvoiceBuilder::new(Currency::Bitcoin)
        .description_hash(sha256::Hash::hash(description.as_bytes()))
        .payment_hash(sha256::Hash::hash(preimage))
        .payment_secret(PaymentSecret([0x11; 32]))
        .amount_milli_satoshis(amount_msat)
        .duration_since_epoch(Duration::from_secs(CLOCK.load(Ordering::SeqCst)))
        .expiry_time(Duration::from_secs(expiry))
        .min_final_cltv_expiry_delta(18)
        .build_signed(|hash| secp.sign_ecdsa_recoverable(hash, &sk))
        .unwrap()
        .to_string()
}

struct Issued {
    bolt11: String,
    label: String,
    preimage: [u8; 32],
    paid: bool,
}

/// Node stand-in: signs request-bound invoices, remembers them, and lets the
/// test mark one paid.
#[derive(Default)]
struct FakeReceiver {
    invoices: StdMutex<HashMap<String, Issued>>,
    counter: AtomicU64,
}

impl FakeReceiver {
    fn pay(&self, payment_hash_hex: &str) -> String {
        let mut invoices = self.invoices.lock().unwrap();
        let issued = invoices.get_mut(payment_hash_hex).expect("known invoice");
        issued.paid = true;
        hex::encode(issued.preimage)
    }

    fn insert_foreign(&self, payment_hash_hex: &str) {
        self.invoices.lock().unwrap().insert(
            payment_hash_hex.to_owned(),
            Issued {
                bolt11: String::new(),
                label: "mint-quote-1".into(),
                preimage: [0u8; 32],
                paid: true,
            },
        );
    }
}

#[async_trait]
impl InvoiceSource for FakeReceiver {
    async fn create_invoice(
        &self,
        amount_msat: u64,
        description: &str,
        expiry_secs: u64,
    ) -> Result<CreatedInvoice, ReceiverError> {
        let n = self.counter.fetch_add(1, Ordering::SeqCst) + 1;
        let mut preimage = [0u8; 32];
        preimage[..8].copy_from_slice(&n.to_be_bytes());
        preimage[31] = 0x5a;
        let bolt11 = sign_invoice(description, amount_msat, expiry_secs, &preimage);
        let payment_hash_hex = hex::encode(sha256::Hash::hash(&preimage).as_ref() as &[u8]);
        let label = format!("bpir-x402-{n:04}");
        self.invoices.lock().unwrap().insert(
            payment_hash_hex.clone(),
            Issued {
                bolt11: bolt11.clone(),
                label: label.clone(),
                preimage,
                paid: false,
            },
        );
        Ok(CreatedInvoice {
            bolt11,
            payment_hash_hex,
            label,
        })
    }

    async fn lookup(&self, payment_hash_hex: &str) -> Result<Option<InvoiceState>, ReceiverError> {
        Ok(self
            .invoices
            .lock()
            .unwrap()
            .get(payment_hash_hex)
            .map(|i| InvoiceState {
                label: i.label.clone(),
                status: if i.paid { "paid" } else { "unpaid" }.to_owned(),
                bolt11: Some(i.bolt11.clone()),
                preimage_hex: i.paid.then(|| hex::encode(i.preimage)),
            }))
    }
}

/// The Cashu path is not exercised here.
struct NoSwapper;

#[async_trait]
impl Swapper for NoSwapper {
    async fn receive(&self, _: &TokenSummary, _: &str) -> Result<u64, SwapError> {
        Err(SwapError::Rejected("no mint in this test".into()))
    }
}

struct Harness {
    app: axum::Router,
    state: Arc<AppState>,
    receiver: Arc<FakeReceiver>,
    _dir: tempfile::TempDir,
}

fn harness() -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let config: Config = toml::from_str(&format!(
        r#"
        listen = "127.0.0.1:0"
        grant_key_path = "{0}/grant.key"
        wallet_seed_path = "{0}/wallet.seed"
        wallet_db_path = "{0}/wallet.sqlite"
        store_path = "{0}/grants.jsonl"
        mints = ["https://mint.example"]
        [arc]
        seed_path = "{0}/arc.seed"
        presentation_limit = 4
        [[arc.credential_offers]]
        credits = 4
        sat = 40
        [x402]
        guard_socket = "{0}/guard.sock"
        node_pubkey_hex = "{KEY_ONE_PUBKEY}"
        public_url = "{PUBLIC_URL}"
        invoices_per_minute_per_ip = 2
        "#,
        dir.path().display()
    ))
    .unwrap();
    let receiver = Arc::new(FakeReceiver::default());
    let x402 = X402State::new(
        config.x402.clone().unwrap(),
        Box::new(SharedReceiver(Arc::clone(&receiver))),
    )
    .unwrap();
    let store = Store::open(&config.store_path).unwrap();
    let redeem_store = RedeemStore::open(&config.redeem_store_path()).unwrap();
    let state = Arc::new(AppState {
        config,
        issuer: IssuerKey::new(&[5u8; 32]),
        swapper: Box::new(NoSwapper),
        store: Mutex::new(store),
        redeem_store: Mutex::new(redeem_store),
        operator_keys: vec![],
        arc: Some(ArcIssuer::new([9u8; 32], ARC_EPOCH, ARC_GRACE, 4)),
        x402: Some(x402),
        clock: Box::new(|| CLOCK.load(Ordering::SeqCst)),
    });
    Harness {
        app: build_router(Arc::clone(&state)),
        state,
        receiver,
        _dir: dir,
    }
}

/// `Box<dyn InvoiceSource>` over a shared fake, so the test keeps a handle.
struct SharedReceiver(Arc<FakeReceiver>);

#[async_trait]
impl InvoiceSource for SharedReceiver {
    async fn create_invoice(
        &self,
        amount_msat: u64,
        description: &str,
        expiry_secs: u64,
    ) -> Result<CreatedInvoice, ReceiverError> {
        self.0
            .create_invoice(amount_msat, description, expiry_secs)
            .await
    }
    async fn lookup(&self, payment_hash_hex: &str) -> Result<Option<InvoiceState>, ReceiverError> {
        self.0.lookup(payment_hash_hex).await
    }
}

async fn post(
    app: &axum::Router,
    body: &str,
    extra: &[(&str, String)],
) -> (StatusCode, axum::http::HeaderMap, Value) {
    let mut req = Request::builder()
        .method(Method::POST)
        .uri("/v2/credentials")
        .header(header::CONTENT_TYPE, "application/json");
    for (k, v) in extra {
        req = req.header(*k, v.as_str());
    }
    let response = app
        .clone()
        .oneshot(req.body(Body::from(body.to_owned())).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, headers, value)
}

async fn get(app: &axum::Router, path: &str) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(path)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn body_for(request_hex: &str) -> String {
    json!({ "credits": 4, "sat": 40, "request_hex": request_hex }).to_string()
}

#[tokio::test]
async fn challenge_pay_and_settle_issue_one_credential_per_payment() {
    let h = harness();
    let now = CLOCK.load(Ordering::SeqCst);
    let epoch = epoch_at(now, ARC_EPOCH);
    let (_secrets, request) =
        create_credential_request(&request_context(epoch), &mut rand_core::OsRng).unwrap();
    let body = body_for(&hex::encode(request.to_bytes()));

    // 1. No token, no signature: a 402 with a request-bound invoice.
    let (status, headers, json_body) = post(&h.app, &body, &[]).await;
    assert_eq!(status, StatusCode::PAYMENT_REQUIRED, "{json_body}");
    let required: PaymentRequired =
        parse_header(headers["payment-required"].to_str().unwrap()).unwrap();
    assert_eq!(serde_json::to_value(&required).unwrap(), json_body);
    assert_eq!(required.x402_version, 2);
    assert_eq!(
        required.resource.url,
        format!("{PUBLIC_URL}/v2/credentials")
    );
    let accepted = required.accepts[0].clone();
    assert_eq!(accepted.scheme, "exact");
    assert_eq!(accepted.network, "lnbtc:000000000019d6689c085ae165831e93");
    assert_eq!(accepted.amount, "40000");
    assert_eq!(accepted.asset, "BTC");
    assert_eq!(accepted.pay_to, KEY_ONE_PUBKEY);
    assert_eq!(accepted.max_timeout_seconds, 900);
    assert_eq!(accepted.extra_str("paymentFlow"), Some("upfront"));
    assert_eq!(accepted.extra_str("requestBindingProfile"), Some("http:1"));
    assert_eq!(
        accepted.extra["requestBindingParams"],
        json!({"headers": ["content-type"]})
    );
    let expected = http1(
        "POST",
        &format!("{PUBLIC_URL}/v2/credentials"),
        body.as_bytes(),
        &[BoundHeader {
            name: "content-type",
            value: Some("application/json"),
        }],
    );
    assert_eq!(
        accepted.extra_str("requestHash"),
        Some(expected.request_hash_hex().as_str())
    );
    let invoice: Bolt11Invoice = accepted.extra_str("invoice").unwrap().parse().unwrap();
    assert_eq!(
        hex::encode(invoice.recover_payee_pub_key().serialize()),
        KEY_ONE_PUBKEY
    );
    assert_eq!(invoice.amount_milli_satoshis(), Some(40_000));
    let payment_hash = hex::encode(invoice.payment_hash().as_ref() as &[u8]);

    // Unpaid: the status endpoint says so without a preimage.
    let (status, state) = get(&h.app, &format!("/v2/x402/invoices/{payment_hash}")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(state["status"], "unpaid");
    assert!(state["preimage"].is_null());

    // 2. Pay, then retry with the preimage.
    let preimage = h.receiver.pay(&payment_hash);
    let payload = PaymentPayload {
        x402_version: 2,
        resource: Some(required.resource.clone()),
        accepted: accepted.clone(),
        payload: serde_json::from_value(json!({ "preimage": preimage })).unwrap(),
    };
    let signature = header_value(&payload);
    let (status, headers, issued) =
        post(&h.app, &body, &[("payment-signature", signature.clone())]).await;
    assert_eq!(status, StatusCode::OK, "{issued}");
    let settlement: SettlementResponse =
        parse_header(headers["payment-response"].to_str().unwrap()).unwrap();
    assert!(settlement.success);
    assert_eq!(settlement.transaction, payment_hash);
    assert_eq!(settlement.network, accepted.network);
    assert_eq!(issued["epoch"], epoch);
    assert_eq!(issued["presentation_limit"], 4);
    assert!(issued["response_hex"].as_str().unwrap().len() > 64);

    // 3. The identical retry replays the stored answer.
    let (status, _, again) = post(&h.app, &body, &[("payment-signature", signature.clone())]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(again, issued);

    // 4. The same proof with another request: the binding differs.
    let (_, other) =
        create_credential_request(&request_context(epoch), &mut rand_core::OsRng).unwrap();
    let other_body = body_for(&hex::encode(other.to_bytes()));
    let (status, headers, refused) = post(
        &h.app,
        &other_body,
        &[("payment-signature", signature.clone())],
    )
    .await;
    assert_eq!(status, StatusCode::PAYMENT_REQUIRED, "{refused}");
    let failure: SettlementResponse =
        parse_header(headers["payment-response"].to_str().unwrap()).unwrap();
    assert!(!failure.success);
    assert_eq!(
        failure.error_reason.as_deref(),
        Some("invalid_exact_lnbtc_request_mismatch")
    );

    // 5. A wrong preimage for the right request.
    let mut wrong = payload.clone();
    wrong.payload["preimage"] = json!("ab".repeat(32));
    let (status, headers, _) = post(
        &h.app,
        &body,
        &[("payment-signature", header_value(&wrong))],
    )
    .await;
    assert_eq!(status, StatusCode::PAYMENT_REQUIRED);
    let failure: SettlementResponse =
        parse_header(headers["payment-response"].to_str().unwrap()).unwrap();
    assert_eq!(
        failure.error_reason.as_deref(),
        Some("invalid_exact_lnbtc_preimage_hash_mismatch")
    );

    // 6. Paid: the status endpoint now hands the browser the preimage.
    let (status, state) = get(&h.app, &format!("/v2/x402/invoices/{payment_hash}")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(state["status"], "paid");
    assert_eq!(state["preimage"], preimage);

    // The store carries the settlement, keyed by network and payment hash.
    let key = format!("x402:{}:{payment_hash}", accepted.network);
    assert!(h.state.store.lock().await.get(&key).is_some());
}

#[tokio::test]
async fn status_hides_foreign_invoices_and_rejects_bad_hashes() {
    let h = harness();
    let foreign = "ab".repeat(32);
    h.receiver.insert_foreign(&foreign);
    let (status, _) = get(&h.app, &format!("/v2/x402/invoices/{foreign}")).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "mint invoices are invisible");
    let (status, _) = get(&h.app, &format!("/v2/x402/invoices/{}", "cd".repeat(32))).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = get(&h.app, "/v2/x402/invoices/nothex").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn challenges_are_rate_limited_per_address_and_signatures_must_decode() {
    let h = harness();
    let now = CLOCK.load(Ordering::SeqCst);
    let (_, request) = create_credential_request(
        &request_context(epoch_at(now, ARC_EPOCH)),
        &mut rand_core::OsRng,
    )
    .unwrap();
    let body = body_for(&hex::encode(request.to_bytes()));
    let ip = [("cf-connecting-ip", "203.0.113.7".to_owned())];
    for _ in 0..2 {
        let (status, _, _) = post(&h.app, &body, &ip).await;
        assert_eq!(status, StatusCode::PAYMENT_REQUIRED);
    }
    let (status, _, refused) = post(&h.app, &body, &ip).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{refused}");
    // Another address still gets a challenge.
    let (status, _, _) = post(
        &h.app,
        &body,
        &[("cf-connecting-ip", "203.0.113.8".to_owned())],
    )
    .await;
    assert_eq!(status, StatusCode::PAYMENT_REQUIRED);
    // A signature that is not base64 JSON is a 400, not a settlement failure.
    let (status, _, _) = post(&h.app, &body, &[("payment-signature", "!!!".to_owned())]).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    // A pack that is not on sale.
    let (status, _, _) = post(
        &h.app,
        &json!({"credits": 5, "sat": 40, "request_hex": "00"}).to_string(),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}
