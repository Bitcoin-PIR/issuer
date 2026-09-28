//! Strict BOLT11 checks against one payment requirement (scheme spec,
//! "PaymentRequirements" checks 1–6 and "Facilitator Validation" step 5).
//! Signature validity is checked by the parser; the payee key is recovered
//! from the signature, so no node access is needed.

use super::Network;
use lightning_invoice::{Bolt11Invoice, Bolt11InvoiceDescriptionRef, Currency};

/// What the invoice must commit to.
pub struct Expected<'a> {
    pub network: Network,
    pub amount_msat: u64,
    /// 66 lowercase hex characters (compressed secp256k1 key).
    pub pay_to_hex: &'a str,
    pub request_hash: &'a [u8; 32],
    pub max_timeout_secs: u64,
    pub now_unix: u64,
    pub clock_skew_secs: u64,
}

/// Facts read from a valid invoice.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvoiceFacts {
    pub payment_hash: [u8; 32],
    pub created_at: u64,
    pub expiry_secs: u64,
}

impl InvoiceFacts {
    pub fn payment_hash_hex(&self) -> String {
        hex::encode(self.payment_hash)
    }

    /// `invoice_creation_time + invoice_expiry_seconds`.
    pub fn end(&self) -> u64 {
        self.created_at.saturating_add(self.expiry_secs)
    }

    /// Server-side rule: the challenge must still be payable.
    pub fn is_unexpired_at(&self, now_unix: u64) -> bool {
        now_unix <= self.end()
    }

    /// Facilitator rule ("Paid-but-expired Policy"): settlement passes while
    /// `settlement_time <= invoice_end + skew`.
    pub fn within_settlement_window(&self, now_unix: u64, skew_secs: u64) -> bool {
        now_unix <= self.end().saturating_add(skew_secs)
    }
}

/// Decodes and checks `bolt11`. Errors are the spec's `errorReason` strings.
pub fn check(bolt11: &str, expected: &Expected<'_>) -> Result<InvoiceFacts, &'static str> {
    let invoice: Bolt11Invoice = bolt11
        .trim()
        .parse()
        .map_err(|_| "invalid_exact_lnbtc_invoice_decode_failed")?;
    let description_hash = match invoice.description() {
        Bolt11InvoiceDescriptionRef::Hash(h) => to_array(h.0.as_ref()),
        Bolt11InvoiceDescriptionRef::Direct(_) => {
            return Err("invalid_exact_lnbtc_invoice_description")
        }
    };
    if &description_hash != expected.request_hash {
        return Err("invalid_exact_lnbtc_invoice_request_mismatch");
    }
    let recovered = hex::encode(invoice.recover_payee_pub_key().serialize());
    if recovered != expected.pay_to_hex {
        return Err("invalid_exact_lnbtc_invoice_payee_mismatch");
    }
    if let Some(n) = invoice.payee_pub_key() {
        if hex::encode(n.serialize()) != expected.pay_to_hex {
            return Err("invalid_exact_lnbtc_invoice_payee_mismatch");
        }
    }
    let currency_ok = matches!(
        (expected.network, invoice.currency()),
        (Network::Mainnet, Currency::Bitcoin) | (Network::Testnet, Currency::BitcoinTestnet)
    );
    if !currency_ok {
        return Err("invalid_exact_lnbtc_invoice_currency_mismatch");
    }
    if invoice.amount_milli_satoshis() != Some(expected.amount_msat) {
        return Err("invalid_exact_lnbtc_invoice_amount_mismatch");
    }
    let expiry_secs = invoice.expiry_time().as_secs();
    if expiry_secs != expected.max_timeout_secs {
        return Err("invalid_exact_lnbtc_invoice_expiry_mismatch");
    }
    let created_at = invoice.duration_since_epoch().as_secs();
    if created_at > expected.now_unix.saturating_add(expected.clock_skew_secs) {
        return Err("invalid_exact_lnbtc_invoice_created_in_future");
    }
    Ok(InvoiceFacts {
        payment_hash: to_array(invoice.payment_hash().as_ref()),
        created_at,
        expiry_secs,
    })
}

fn to_array(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes);
    out
}
