//! x402 `exact/lnbtc` over the HTTP layer with a fake receiver that signs
//! invoices with secp256k1 key 1 (`payTo` 0279be…), the specification's
//! test key, and a scripted stand-in for the mint side of ecash sales.
//! Nothing here touches a node, a mint, or the network.

use std::collections::HashMap;
use std::str::FromStr;
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
use bpir_issuer::config::{Config, X402Config};
use bpir_issuer::ecash::{EcashSeller, SaleKeyset, SellError};
use bpir_issuer::issuer_key::IssuerKey;
use bpir_issuer::redeem::RedeemStore;
use bpir_issuer::store::{State as TokenState, Store};
use bpir_issuer::x402::binding::{http1, BoundHeader};
use bpir_issuer::x402::receiver::{CreatedInvoice, InvoiceSource, InvoiceState, ReceiverError};
use bpir_issuer::x402::server::X402State;
use bpir_issuer::x402::{
    header_value, parse_header, PaymentPayload, PaymentRequired, SettlementResponse,
};
use cdk::amount::{FeeAndAmounts, SplitTarget};
use cdk::nuts::{
    BlindSignature, BlindSignatureDleq, BlindedMessage, Id, PreMintSecrets,
    SecretKey as CashuSecretKey,
};
use cdk::Amount;
use http_body_util::BodyExt;
use lightning_invoice::{Bolt11Invoice, Currency, InvoiceBuilder, PaymentSecret};
use pir_credit::arc::{epoch_at, request_context};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;
use tower::ServiceExt;

const KEY_ONE_PUBKEY: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const PUBLIC_URL: &str = "https://issuer.example";
const KEYSET_ID: &str = "009a1f293253e41e";
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

/// What the stand-in mint does with the next sale.
enum Sale {
    /// Sign the outputs and answer.
    Sign,
    /// Sign the outputs but lose the answer (outcome unknown to the issuer).
    Lose,
    /// Fail without signing.
    Fail(SellError),
}

/// Mint side of ecash sales: "signs" an output by echoing its `B_` as `C_`
/// (with a fixed DLEQ), remembers what it signed for restore, refuses to
/// sign an output twice, and follows a script of sale outcomes.
struct FakeSeller {
    keyset: SaleKeyset,
    float: AtomicU64,
    script: StdMutex<Vec<Sale>>,
    signed: StdMutex<Vec<BlindSignature>>,
    sales: AtomicU64,
    restores: AtomicU64,
}

impl FakeSeller {
    fn new() -> Self {
        Self {
            keyset: SaleKeyset {
                id: Id::from_str(KEYSET_ID).unwrap(),
                amounts: (0..32).map(|i| 1u64 << i).collect(),
                input_fee_ppk: 0,
            },
            float: AtomicU64::new(1_210),
            script: StdMutex::new(Vec::new()),
            signed: StdMutex::new(Vec::new()),
            sales: AtomicU64::new(0),
            restores: AtomicU64::new(0),
        }
    }

    fn signature(output: &BlindedMessage) -> BlindSignature {
        BlindSignature {
            amount: output.amount,
            keyset_id: output.keyset_id,
            c: output.blinded_secret,
            dleq: Some(BlindSignatureDleq {
                e: CashuSecretKey::from_slice(&[1; 32]).unwrap(),
                s: CashuSecretKey::from_slice(&[2; 32]).unwrap(),
            }),
        }
    }

    fn signed_for(&self, output: &BlindedMessage) -> Option<BlindSignature> {
        self.signed
            .lock()
            .unwrap()
            .iter()
            .find(|s| s.c == output.blinded_secret)
            .cloned()
    }
}

#[async_trait]
impl EcashSeller for FakeSeller {
    async fn keyset(&self) -> Result<SaleKeyset, SellError> {
        Ok(self.keyset.clone())
    }

    async fn spendable(&self) -> Result<u64, SellError> {
        Ok(self.float.load(Ordering::SeqCst))
    }

    async fn sell(
        &self,
        _sale: &str,
        _sat: u64,
        outputs: &[BlindedMessage],
    ) -> Result<Vec<BlindSignature>, SellError> {
        self.sales.fetch_add(1, Ordering::SeqCst);
        if outputs.iter().any(|o| self.signed_for(o).is_some()) {
            return Err(SellError::AlreadySigned);
        }
        let next = {
            let mut script = self.script.lock().unwrap();
            if script.is_empty() {
                Sale::Sign
            } else {
                script.remove(0)
            }
        };
        let signatures: Vec<BlindSignature> = outputs.iter().map(Self::signature).collect();
        match next {
            Sale::Sign => {
                self.signed.lock().unwrap().extend(signatures.clone());
                Ok(signatures)
            }
            Sale::Lose => {
                self.signed.lock().unwrap().extend(signatures);
                Err(SellError::Unknown("connection reset after sending".into()))
            }
            Sale::Fail(error) => Err(error),
        }
    }

    async fn restore(
        &self,
        _sale: &str,
        outputs: &[BlindedMessage],
    ) -> Result<Option<Vec<BlindSignature>>, SellError> {
        self.restores.fetch_add(1, Ordering::SeqCst);
        let found: Vec<BlindSignature> =
            outputs.iter().filter_map(|o| self.signed_for(o)).collect();
        match found.len() {
            0 => Ok(None),
            n if n == outputs.len() => Ok(Some(found)),
            _ => Err(SellError::Unknown("partly signed".into())),
        }
    }
}

/// `Box<dyn EcashSeller>` over a shared fake, so the test keeps a handle.
struct SharedSeller(Arc<FakeSeller>);

#[async_trait]
impl EcashSeller for SharedSeller {
    async fn keyset(&self) -> Result<SaleKeyset, SellError> {
        self.0.keyset().await
    }
    async fn spendable(&self) -> Result<u64, SellError> {
        self.0.spendable().await
    }
    async fn sell(
        &self,
        sale: &str,
        sat: u64,
        outputs: &[BlindedMessage],
    ) -> Result<Vec<BlindSignature>, SellError> {
        self.0.sell(sale, sat, outputs).await
    }
    async fn restore(
        &self,
        sale: &str,
        outputs: &[BlindedMessage],
    ) -> Result<Option<Vec<BlindSignature>>, SellError> {
        self.0.restore(sale, outputs).await
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
    seller: Arc<FakeSeller>,
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
    let seller = Arc::new(FakeSeller::new());
    let store = Store::open(&config.store_path).unwrap();
    let redeem_store = RedeemStore::open(&config.redeem_store_path()).unwrap();
    let state = Arc::new(AppState {
        config,
        issuer: IssuerKey::new(&[5u8; 32]),
        swapper: Box::new(NoSwapper),
        seller: Box::new(SharedSeller(Arc::clone(&seller))),
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
        seller,
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
    post_to(app, "/v2/credentials", body, extra).await
}

async fn post_to(
    app: &axum::Router,
    path: &str,
    body: &str,
    extra: &[(&str, String)],
) -> (StatusCode, axum::http::HeaderMap, Value) {
    let mut req = Request::builder()
        .method(Method::POST)
        .uri(path)
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

const ECASH: &str = "/v2/x402/ecash";

#[test]
fn ecash_limits_default_for_older_configs_and_must_be_ordered() {
    // An `[x402]` table written before ecash sales parses with the defaults.
    let mut config: X402Config = toml::from_str(&format!(
        r#"
        guard_socket = "/run/guard.sock"
        node_pubkey_hex = "{KEY_ONE_PUBKEY}"
        public_url = "{PUBLIC_URL}"
        "#
    ))
    .unwrap();
    assert_eq!((config.ecash_min_sat, config.ecash_max_sat), (10, 20_000));
    assert!(X402State::new(config.clone(), Box::new(FakeReceiver::default())).is_ok());
    config.ecash_min_sat = 20_001;
    assert!(X402State::new(config, Box::new(FakeReceiver::default())).is_err());
}

/// A client's purchase of `sat`: outputs blinded with fresh secrets, as the
/// web client builds them, and the exact body bytes it sends twice.
fn ecash_body(sat: u64) -> (Vec<BlindedMessage>, String) {
    let keyset = FakeSeller::new().keyset;
    let fee_and_amounts: FeeAndAmounts = (0, keyset.amounts).into();
    let premint = PreMintSecrets::random(
        keyset.id,
        Amount::from(sat),
        &SplitTarget::None,
        &fee_and_amounts,
    )
    .unwrap();
    let outputs = premint.blinded_messages();
    let body = json!({
        "sat": sat,
        "outputs": outputs.iter().map(|o| json!({
            "amount": o.amount.to_u64(),
            "id": o.keyset_id.to_string(),
            "B_": o.blinded_secret.to_hex(),
        })).collect::<Vec<_>>(),
    })
    .to_string();
    (outputs, body)
}

/// Asks for the challenge, pays its invoice, and returns the
/// `PAYMENT-SIGNATURE` value and the payment hash.
async fn pay_for(h: &Harness, body: &str) -> (String, String) {
    let (status, headers, challenge) = post_to(&h.app, ECASH, body, &[]).await;
    assert_eq!(status, StatusCode::PAYMENT_REQUIRED, "{challenge}");
    let required: PaymentRequired =
        parse_header(headers["payment-required"].to_str().unwrap()).unwrap();
    let accepted = required.accepts[0].clone();
    let invoice: Bolt11Invoice = accepted.extra_str("invoice").unwrap().parse().unwrap();
    let payment_hash = hex::encode(invoice.payment_hash().as_ref() as &[u8]);
    let preimage = h.receiver.pay(&payment_hash);
    let payload = PaymentPayload {
        x402_version: 2,
        resource: Some(required.resource),
        accepted,
        payload: serde_json::from_value(json!({ "preimage": preimage })).unwrap(),
    };
    (header_value(&payload), payment_hash)
}

fn ecash_key(payment_hash: &str) -> String {
    format!("x402:lnbtc:000000000019d6689c085ae165831e93:{payment_hash}")
}

#[tokio::test]
async fn ecash_challenge_binds_the_outputs_and_checks_the_float() {
    let h = harness();
    let (outputs, body) = ecash_body(1000);
    let (status, headers, json_body) = post_to(&h.app, ECASH, &body, &[]).await;
    assert_eq!(status, StatusCode::PAYMENT_REQUIRED, "{json_body}");
    let required: PaymentRequired =
        parse_header(headers["payment-required"].to_str().unwrap()).unwrap();
    assert_eq!(serde_json::to_value(&required).unwrap(), json_body);
    assert_eq!(required.resource.url, format!("{PUBLIC_URL}{ECASH}"));
    assert_eq!(
        required.resource.description.as_deref(),
        Some("BitcoinPIR ecash: 1000 sat")
    );
    let accepted = &required.accepts[0];
    assert_eq!(accepted.scheme, "exact");
    assert_eq!(accepted.network, "lnbtc:000000000019d6689c085ae165831e93");
    assert_eq!(accepted.amount, "1000000");
    assert_eq!(accepted.pay_to, KEY_ONE_PUBKEY);
    let expected = http1(
        "POST",
        &format!("{PUBLIC_URL}{ECASH}"),
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
    assert_eq!(invoice.amount_milli_satoshis(), Some(1_000_000));

    // Bodies the contract refuses never get an invoice.
    let point = outputs[0].blinded_secret.to_hex();
    let output = |amount: u64, id: &str| json!({"amount": amount, "id": id, "B_": point});
    for (bad, reason) in [
        (
            json!({"sat": 8, "outputs": [output(8, KEYSET_ID)]}),
            "between 10 and 20000",
        ),
        (
            json!({"sat": 12, "outputs": [output(12, KEYSET_ID)]}),
            "power of two",
        ),
        (
            json!({"sat": 16, "outputs": [output(32, KEYSET_ID)]}),
            "sum to 32",
        ),
        (
            json!({"sat": 16, "outputs": [output(16, "00ffd48b8f5ecf80")]}),
            "not the active",
        ),
        (json!({"sat": 16, "outputs": []}), "1 to 256"),
        (json!({"sat": 16}), "outputs"),
    ] {
        let (status, _, refused) = post_to(&h.app, ECASH, &bad.to_string(), &[]).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}");
        assert_eq!(refused["error"], "invalid_request");
        assert!(
            refused["message"].as_str().unwrap().contains(reason),
            "{refused}"
        );
    }

    // An absurd `sat` is refused before anything prices it, paid or not.
    let huge = json!({"sat": u64::MAX, "outputs": [output(1, KEYSET_ID)]}).to_string();
    let signed = [("payment-signature", "e30=".to_owned())];
    let (status, _, refused) = post_to(&h.app, ECASH, &huge, &signed).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
    assert!(refused["message"].as_str().unwrap().contains("between"));

    // More than the wallet holds: no invoice either.
    h.seller.float.store(999, Ordering::SeqCst);
    let (status, _, refused) = post_to(&h.app, ECASH, &body, &[]).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{refused}");
    assert_eq!(refused["error"], "float_exhausted");
    assert_eq!(h.seller.sales.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn ecash_paid_retry_answers_signatures_in_output_order_once_per_payment() {
    let h = harness();
    let (outputs, body) = ecash_body(1000);
    let (signature, payment_hash) = pay_for(&h, &body).await;
    let paid = [("payment-signature", signature.clone())];
    let (status, headers, sold) = post_to(&h.app, ECASH, &body, &paid).await;
    assert_eq!(status, StatusCode::OK, "{sold}");
    let settlement: SettlementResponse =
        parse_header(headers["payment-response"].to_str().unwrap()).unwrap();
    assert!(settlement.success);
    assert_eq!(settlement.transaction, payment_hash);
    let signatures = sold["signatures"].as_array().unwrap();
    assert_eq!(signatures.len(), outputs.len());
    for (signature, output) in signatures.iter().zip(&outputs) {
        assert_eq!(signature["amount"], output.amount.to_u64());
        assert_eq!(signature["id"], KEYSET_ID);
        assert_eq!(
            signature["C_"],
            output.blinded_secret.to_hex(),
            "the fake echoes B_"
        );
        assert_eq!(
            signature["dleq"],
            json!({"e": "01".repeat(32), "s": "02".repeat(32)})
        );
    }
    // NUT-00 blind signatures, as cdk reads them.
    let parsed: Vec<BlindSignature> = serde_json::from_value(sold["signatures"].clone()).unwrap();
    assert_eq!(parsed[0].c, outputs[0].blinded_secret);

    // The identical retry replays the answer without another sale.
    let (status, _, again) = post_to(&h.app, ECASH, &body, &paid).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(again, sold);
    assert_eq!(h.seller.sales.load(Ordering::SeqCst), 1);
    assert_eq!(h.seller.restores.load(Ordering::SeqCst), 0);
    match h.state.store.lock().await.get(&ecash_key(&payment_hash)) {
        Some(TokenState::X402EcashIssued {
            body_sha256_hex,
            msat,
            signatures,
            ..
        }) => {
            assert_eq!(
                *body_sha256_hex,
                hex::encode(Sha256::digest(body.as_bytes()))
            );
            assert_eq!(*msat, 1_000_000);
            assert_eq!(signatures.len(), outputs.len());
        }
        other => panic!("not issued: {other:?}"),
    }

    // Another body with the same proof fails the request binding.
    let (_, other_body) = ecash_body(1000);
    let (status, headers, _) = post_to(&h.app, ECASH, &other_body, &paid).await;
    assert_eq!(status, StatusCode::PAYMENT_REQUIRED);
    let failure: SettlementResponse =
        parse_header(headers["payment-response"].to_str().unwrap()).unwrap();
    assert_eq!(
        failure.error_reason.as_deref(),
        Some("invalid_exact_lnbtc_request_mismatch")
    );

    // A payment the store already holds for another body is a duplicate.
    let (signature, payment_hash) = pay_for(&h, &other_body).await;
    h.state
        .store
        .lock()
        .await
        .record(
            &ecash_key(&payment_hash),
            TokenState::X402EcashPending {
                network: "lnbtc:000000000019d6689c085ae165831e93".into(),
                payment_hash_hex: payment_hash.clone(),
                msat: 1_000_000,
                body_sha256_hex: "00".repeat(32),
            },
        )
        .unwrap();
    let (status, headers, _) = post_to(
        &h.app,
        ECASH,
        &other_body,
        &[("payment-signature", signature)],
    )
    .await;
    assert_eq!(status, StatusCode::PAYMENT_REQUIRED);
    let failure: SettlementResponse =
        parse_header(headers["payment-response"].to_str().unwrap()).unwrap();
    assert_eq!(
        failure.error_reason.as_deref(),
        Some("duplicate_settlement")
    );
    assert_eq!(h.seller.sales.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn ecash_sale_with_a_lost_answer_is_finished_by_restore() {
    let h = harness();
    h.seller.script.lock().unwrap().push(Sale::Lose);
    let (outputs, body) = ecash_body(10);
    let (signature, payment_hash) = pay_for(&h, &body).await;
    let paid = [("payment-signature", signature)];
    let (status, _, unfinished) = post_to(&h.app, ECASH, &body, &paid).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{unfinished}");
    assert_eq!(unfinished["error"], "retry");
    assert!(matches!(
        h.state.store.lock().await.get(&ecash_key(&payment_hash)),
        Some(TokenState::X402EcashPending { .. })
    ));

    // The identical retry asks the mint first and finds the outputs signed.
    let (status, _, sold) = post_to(&h.app, ECASH, &body, &paid).await;
    assert_eq!(status, StatusCode::OK, "{sold}");
    let signatures = sold["signatures"].as_array().unwrap();
    assert_eq!(signatures.len(), outputs.len());
    assert_eq!(signatures[0]["C_"], outputs[0].blinded_secret.to_hex());
    assert_eq!(h.seller.sales.load(Ordering::SeqCst), 1);
    assert_eq!(h.seller.restores.load(Ordering::SeqCst), 1);
    assert!(matches!(
        h.state.store.lock().await.get(&ecash_key(&payment_hash)),
        Some(TokenState::X402EcashIssued { .. })
    ));

    // From now on the stored answer is replayed.
    let (status, _, again) = post_to(&h.app, ECASH, &body, &paid).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(again, sold);
    assert_eq!(h.seller.restores.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn ecash_sale_that_failed_after_payment_is_sold_on_the_retry() {
    let h = harness();
    h.seller
        .script
        .lock()
        .unwrap()
        .push(Sale::Fail(SellError::Unavailable("mint down".into())));
    let (outputs, body) = ecash_body(42);
    let (signature, payment_hash) = pay_for(&h, &body).await;
    let paid = [("payment-signature", signature)];
    let (status, _, unfinished) = post_to(&h.app, ECASH, &body, &paid).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{unfinished}");
    assert_eq!(unfinished["error"], "retry");

    // Nothing signed: the retry restores nothing and sells.
    let (status, _, sold) = post_to(&h.app, ECASH, &body, &paid).await;
    assert_eq!(status, StatusCode::OK, "{sold}");
    assert_eq!(sold["signatures"].as_array().unwrap().len(), outputs.len());
    assert_eq!(h.seller.sales.load(Ordering::SeqCst), 2);
    assert_eq!(h.seller.restores.load(Ordering::SeqCst), 1);
    assert!(matches!(
        h.state.store.lock().await.get(&ecash_key(&payment_hash)),
        Some(TokenState::X402EcashIssued { .. })
    ));
}

#[tokio::test]
async fn ecash_outputs_the_mint_signed_before_are_restored_not_sold_twice() {
    // Two payments for the same outputs: the mint refuses to sign them again,
    // and the second sale answers the signatures the mint already holds.
    let h = harness();
    let (_, body) = ecash_body(10);
    let (first, _) = pay_for(&h, &body).await;
    let (status, _, sold) = post_to(&h.app, ECASH, &body, &[("payment-signature", first)]).await;
    assert_eq!(status, StatusCode::OK, "{sold}");
    let (second, _) = pay_for(&h, &body).await;
    let (status, _, again) = post_to(&h.app, ECASH, &body, &[("payment-signature", second)]).await;
    assert_eq!(status, StatusCode::OK, "{again}");
    assert_eq!(again, sold);
    assert_eq!(h.seller.sales.load(Ordering::SeqCst), 2);
    assert_eq!(h.seller.restores.load(Ordering::SeqCst), 1);
}
