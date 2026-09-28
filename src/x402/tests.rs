//! Unit tests over signed invoices: the specification's HTTP test vector
//! (secp256k1 key 1, GET https://api.example.com/article/A) and invoices we
//! sign ourselves with the same key.

use super::binding::http1;
use super::facilitator::{parse_amount, settle};
use super::invoice::{check, Expected};
use super::{Network, PaymentPayload, PaymentRequirements};
use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use lightning_invoice::{Currency, InvoiceBuilder, PaymentSecret};
use serde_json::{json, Map, Value};
use std::time::Duration;

pub const KEY_ONE_PUBKEY: &str =
    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const SPEC_REQUEST_HASH: &str = "0d6623f775e025501fa7f0a30b54da25aad62b6ccfe35c85da38016711e6c018";
const SPEC_INVOICE: &str = "lnbc250n1pj48ugqpp54y3u9s8ylemsv8l3ewyzzu0klhujvuvmkl6llchq23vy8rzjsf0qsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygshp5p4nz8am4uqj4q8a87z3sk4x6yk4dv2mvel34epw68qqkwy0xcqvqxqzfvcqpjr4rx6ls6j5rpwknuea64evlk7yfx56wmqcer5eerekdsn9tlv6v4ex9mlz5dtm9qapl3svwlqcf7837dmjkru9z9w4h2rvm0md52w2sqxrwu5f";
const SPEC_PREIMAGE: &str = "0001020304050607080900010203040506070809000102030405060708090102";
const T0: u64 = 1_700_000_000;

/// Signs an invoice with key 1 for `description_hash`, or an inline
/// description when `inline` is set.
pub fn sign_invoice(
    description_hash: [u8; 32],
    inline: bool,
    amount_msat: u64,
    created: u64,
    expiry: u64,
    preimage: &[u8; 32],
    currency: Currency,
) -> String {
    let secp = Secp256k1::new();
    let mut key = [0u8; 32];
    key[31] = 1;
    let sk = SecretKey::from_slice(&key).unwrap();
    let payment_hash = sha256::Hash::hash(preimage);
    let builder = InvoiceBuilder::new(currency)
        .payment_hash(payment_hash)
        .payment_secret(PaymentSecret([0x11; 32]))
        .amount_milli_satoshis(amount_msat)
        .duration_since_epoch(Duration::from_secs(created))
        .expiry_time(Duration::from_secs(expiry))
        .min_final_cltv_expiry_delta(18);
    let invoice = if inline {
        builder
            .description("inline".to_owned())
            .build_signed(|hash| secp.sign_ecdsa_recoverable(hash, &sk))
            .unwrap()
    } else {
        builder
            .description_hash(sha256::Hash::from_slice(&description_hash).unwrap())
            .build_signed(|hash| secp.sign_ecdsa_recoverable(hash, &sk))
            .unwrap()
    };
    invoice.to_string()
}

/// The specification's own sample string omits the BOLT11 `9` (features)
/// field that a `s` (payment secret) field requires, so a strict decoder
/// rejects it. Every test therefore uses an invoice signed here with the
/// same key, terms, and description hash; the spec string only documents
/// that strictness.
fn spec_invoice() -> String {
    sign_invoice(
        spec_request_hash(),
        false,
        25_000,
        T0,
        300,
        &spec_preimage(),
        Currency::Bitcoin,
    )
}

fn spec_request_hash() -> [u8; 32] {
    let b = http1("GET", "https://api.example.com/article/A", b"", &[]);
    assert_eq!(b.request_hash_hex(), SPEC_REQUEST_HASH);
    b.request_hash
}

fn spec_preimage() -> [u8; 32] {
    let mut p = [0u8; 32];
    hex::decode_to_slice(SPEC_PREIMAGE, &mut p).unwrap();
    p
}

fn expected<'a>(request_hash: &'a [u8; 32], now: u64) -> Expected<'a> {
    Expected {
        network: Network::Mainnet,
        amount_msat: 25_000,
        pay_to_hex: KEY_ONE_PUBKEY,
        request_hash,
        max_timeout_secs: 300,
        now_unix: now,
        clock_skew_secs: 60,
    }
}

#[test]
fn strict_decoding_rejects_the_specification_sample_string() {
    let hash = spec_request_hash();
    assert_eq!(
        check(SPEC_INVOICE, &expected(&hash, T0)).unwrap_err(),
        "invalid_exact_lnbtc_invoice_decode_failed"
    );
}

#[test]
fn decodes_the_specification_invoice() {
    let hash = spec_request_hash();
    let facts = check(&spec_invoice(), &expected(&hash, T0)).unwrap();
    assert_eq!(facts.created_at, T0);
    assert_eq!(facts.expiry_secs, 300);
    assert_eq!(
        facts.payment_hash,
        <[u8; 32]>::from(sha2::Sha256::digest(spec_preimage())),
        "the specification preimage pays the specification invoice"
    );
    assert!(facts.is_unexpired_at(T0 + 300));
    assert!(!facts.is_unexpired_at(T0 + 301));
    assert!(facts.within_settlement_window(T0 + 360, 60));
    assert!(!facts.within_settlement_window(T0 + 361, 60));
}

use sha2::Digest as _;

#[test]
fn our_signed_invoices_match_the_specification_vector() {
    let hash = spec_request_hash();
    let invoice: lightning_invoice::Bolt11Invoice = spec_invoice().parse().unwrap();
    assert_eq!(
        hex::encode(invoice.recover_payee_pub_key().serialize()),
        KEY_ONE_PUBKEY
    );
    let facts = check(&spec_invoice(), &expected(&hash, T0)).unwrap();
    assert_eq!(facts.created_at, T0);
}

#[test]
fn invoice_checks_name_the_failing_term() {
    let hash = spec_request_hash();
    let pre = spec_preimage();
    let cases: Vec<(&str, String, Expected)> = vec![
        (
            "invalid_exact_lnbtc_invoice_description",
            sign_invoice(hash, true, 25_000, T0, 300, &pre, Currency::Bitcoin),
            expected(&hash, T0),
        ),
        (
            "invalid_exact_lnbtc_invoice_amount_mismatch",
            sign_invoice(hash, false, 26_000, T0, 300, &pre, Currency::Bitcoin),
            expected(&hash, T0),
        ),
        (
            "invalid_exact_lnbtc_invoice_expiry_mismatch",
            sign_invoice(hash, false, 25_000, T0, 301, &pre, Currency::Bitcoin),
            expected(&hash, T0),
        ),
        (
            "invalid_exact_lnbtc_invoice_currency_mismatch",
            sign_invoice(hash, false, 25_000, T0, 300, &pre, Currency::BitcoinTestnet),
            expected(&hash, T0),
        ),
        (
            "invalid_exact_lnbtc_invoice_created_in_future",
            sign_invoice(hash, false, 25_000, T0 + 61, 300, &pre, Currency::Bitcoin),
            expected(&hash, T0),
        ),
        (
            "invalid_exact_lnbtc_invoice_decode_failed",
            "lnbc1notaninvoice".to_owned(),
            expected(&hash, T0),
        ),
    ];
    for (reason, invoice, exp) in &cases {
        assert_eq!(check(invoice, exp).unwrap_err(), *reason, "{reason}");
    }
    let other = http1("GET", "https://api.example.com/article/B", b"", &[]).request_hash;
    assert_eq!(
        check(&spec_invoice(), &expected(&other, T0)).unwrap_err(),
        "invalid_exact_lnbtc_invoice_request_mismatch"
    );
    let mut wrong_payee = expected(&hash, T0);
    wrong_payee.pay_to_hex = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
    assert_eq!(
        check(&spec_invoice(), &wrong_payee).unwrap_err(),
        "invalid_exact_lnbtc_invoice_payee_mismatch"
    );
}

fn requirements(invoice: &str) -> PaymentRequirements {
    let mut extra = Map::new();
    extra.insert("paymentFlow".into(), json!("upfront"));
    extra.insert("requestHash".into(), json!(SPEC_REQUEST_HASH));
    extra.insert("requestBindingProfile".into(), json!("http:1"));
    extra.insert("requestBindingParams".into(), json!({"headers": []}));
    extra.insert("invoice".into(), json!(invoice));
    PaymentRequirements {
        scheme: "exact".into(),
        network: Network::Mainnet.caip2().into(),
        amount: "25000".into(),
        asset: "BTC".into(),
        pay_to: KEY_ONE_PUBKEY.into(),
        max_timeout_seconds: 300,
        extra,
    }
}

fn payload(accepted: PaymentRequirements, preimage: &str) -> PaymentPayload {
    let mut p = Map::new();
    p.insert("preimage".into(), Value::String(preimage.into()));
    PaymentPayload {
        x402_version: 2,
        resource: None,
        accepted,
        payload: p,
    }
}

#[test]
fn settles_the_specification_proof_once_per_payment_hash() {
    let req = requirements(&spec_invoice());
    let settled = settle(&req, &payload(req.clone(), SPEC_PREIMAGE), T0 + 10, 60).unwrap();
    assert_eq!(settled.network, Network::Mainnet);
    assert_eq!(
        settled.replay_key,
        format!("{}:{}", Network::Mainnet.caip2(), settled.payment_hash_hex)
    );
    assert_eq!(settled.amount_msat, 25_000);
    assert_eq!(settled.retain_until, T0 + 360);

    // A fresh challenge invoice on the requirements side; the accepted
    // (paid) invoice still settles.
    let mut fresh = requirements(&sign_invoice(
        spec_request_hash(),
        false,
        25_000,
        T0 + 5,
        300,
        &[7u8; 32],
        Currency::Bitcoin,
    ));
    fresh.extra["invoice"] = json!(fresh.extra_str("invoice").unwrap());
    let again = settle(&fresh, &payload(req.clone(), SPEC_PREIMAGE), T0 + 10, 60).unwrap();
    assert_eq!(again.payment_hash_hex, settled.payment_hash_hex);
}

#[test]
fn settle_rejects_mismatches_with_the_specification_reasons() {
    let req = requirements(&spec_invoice());
    let ok = payload(req.clone(), SPEC_PREIMAGE);

    let mut other_amount = ok.clone();
    other_amount.accepted.amount = "26000".into();
    assert_eq!(
        settle(&req, &other_amount, T0, 60).unwrap_err(),
        "invalid_exact_lnbtc_amount_mismatch"
    );

    let bad_preimage = payload(req.clone(), &"ff".repeat(32));
    assert_eq!(
        settle(&req, &bad_preimage, T0, 60).unwrap_err(),
        "invalid_exact_lnbtc_preimage_hash_mismatch"
    );
    let short = payload(req.clone(), "abcd");
    assert_eq!(
        settle(&req, &short, T0, 60).unwrap_err(),
        "invalid_exact_lnbtc_preimage_length"
    );
    let upper = payload(req.clone(), &"FF".repeat(32));
    assert_eq!(
        settle(&req, &upper, T0, 60).unwrap_err(),
        "invalid_exact_lnbtc_preimage_malformed"
    );

    // Article B's digest on both sides: the invoice still commits to A.
    let mut req_b = req.clone();
    req_b.extra["requestHash"] =
        json!("4a99860f75eed1ea8178a5db488e044173bc570c8a6210f2c8590cdf8622d509");
    let pay_b = payload(req_b.clone(), SPEC_PREIMAGE);
    assert_eq!(
        settle(&req_b, &pay_b, T0, 60).unwrap_err(),
        "invalid_exact_lnbtc_invoice_request_mismatch"
    );
    // Only the accepted side changed: request mismatch.
    let mut accepted_b = ok.clone();
    accepted_b.accepted.extra["requestHash"] = req_b.extra["requestHash"].clone();
    assert_eq!(
        settle(&req, &accepted_b, T0, 60).unwrap_err(),
        "invalid_exact_lnbtc_request_mismatch"
    );
    // Missing binding fields fail rather than disable the check.
    let mut no_profile = req.clone();
    no_profile.extra.remove("requestBindingProfile");
    assert_eq!(
        settle(&no_profile, &ok, T0, 60).unwrap_err(),
        "invalid_exact_lnbtc_request_binding"
    );
    // Paid but expired beyond the window.
    assert_eq!(
        settle(&req, &ok, T0 + 361, 60).unwrap_err(),
        "invalid_exact_lnbtc_invoice_expired"
    );
    assert!(settle(&req, &ok, T0 + 360, 60).is_ok());
    // Wrong flow on the accepted side.
    let mut flow = ok.clone();
    flow.accepted.extra["paymentFlow"] = json!("deferred");
    assert_eq!(
        settle(&req, &flow, T0, 60).unwrap_err(),
        "invalid_exact_lnbtc_payment_flow"
    );
}

#[test]
fn amounts_are_strict_decimal_integers() {
    assert_eq!(parse_amount("1000"), Some(1000));
    assert_eq!(parse_amount("0"), None);
    assert_eq!(parse_amount("-1"), None);
    assert_eq!(parse_amount("1.0"), None);
    assert_eq!(parse_amount("1e3"), None);
    assert_eq!(parse_amount(""), None);
}
