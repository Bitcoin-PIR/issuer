//! Cashu ecash sold over x402 (`POST /v2/x402/ecash`): the client sends
//! blinded outputs, and once its Lightning payment settles the issuer swaps
//! proofs from its own wallet into exactly those outputs at the mint and
//! answers the blind signatures. The client unblinds them itself, so the
//! issuer never sees the proofs it sold.
//!
//! [`check`] validates a request against the mint's active keyset before
//! anything is paid; the [`EcashSeller`] trait isolates the mint round trips
//! so the HTTP layer is tested with a fake, and [`CdkSeller`] implements it
//! over the issuer's `cdk` wallet.

use std::future::Future;
use std::str::FromStr;
use std::time::Duration;

use cdk::amount::{FeeAndAmounts, SplitTarget};
use cdk::nuts::nut00::ProofsMethods;
use cdk::nuts::{
    nut12, BlindSignature, BlindedMessage, CheckStateRequest, Id, Proof, Proofs, PublicKey,
    RestoreRequest, State, SwapRequest,
};
use cdk::wallet::Wallet;
use cdk::Amount;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::x402::is_lower_hex;

/// Outputs one purchase may carry.
pub const MAX_OUTPUTS: usize = 256;

/// Domain separator for the wallet operation a sale's inputs are reserved
/// under ([`operation_id`]).
const SALE_OPERATION_DOMAIN: &[u8] = b"BPIR-ISSUER-ECASH-SALE-V1";

/// `POST /v2/x402/ecash` body: what to buy and where the mint should sign it.
#[derive(Clone, Debug, Deserialize)]
pub struct EcashRequest {
    pub sat: u64,
    pub outputs: Vec<RequestedOutput>,
}

/// One NUT-00 `BlindedMessage` as the client sent it.
#[derive(Clone, Debug, Deserialize)]
pub struct RequestedOutput {
    pub amount: u64,
    /// Keyset id, lowercase hex.
    pub id: String,
    /// Compressed secp256k1 point, 66 lowercase hex.
    #[serde(rename = "B_")]
    pub blinded_secret: String,
}

/// One NUT-00 `BlindSignature` with its NUT-12 DLEQ proof when the mint sent
/// one: the answer to the client, and what the store keeps for a replay.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EcashSignature {
    pub amount: u64,
    pub id: String,
    #[serde(rename = "C_")]
    pub c: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dleq: Option<EcashDleq>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EcashDleq {
    pub e: String,
    pub s: String,
}

impl From<&BlindSignature> for EcashSignature {
    fn from(signature: &BlindSignature) -> Self {
        Self {
            amount: signature.amount.to_u64(),
            id: signature.keyset_id.to_string(),
            c: signature.c.to_hex(),
            dleq: signature.dleq.as_ref().map(|dleq| EcashDleq {
                e: dleq.e.to_secret_hex(),
                s: dleq.s.to_secret_hex(),
            }),
        }
    }
}

/// The mint's active `sat` keyset, as a sale needs it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SaleKeyset {
    pub id: Id,
    /// Amounts the keyset has a key for, ascending.
    pub amounts: Vec<u64>,
    pub input_fee_ppk: u64,
}

impl SaleKeyset {
    fn fee_and_amounts(&self) -> FeeAndAmounts {
        (self.input_fee_ppk, self.amounts.clone()).into()
    }

    /// The keyset's split of `total` (largest denominations first): the
    /// inputs a sale of that value spends.
    fn split(&self, total: u64) -> Option<Vec<Amount>> {
        Amount::from(total).split(&self.fee_and_amounts()).ok()
    }
}

/// Checks a request against the contract: `sat` within the configured
/// limits, 1 to [`MAX_OUTPUTS`] outputs whose amounts are powers of two the
/// active keyset has keys for and sum to `sat`, every `id` the active keyset,
/// every `B_` a compressed point, no `B_` twice. Returns the outputs as NUT-00
/// blinded messages in request order.
pub fn check(
    request: &EcashRequest,
    keyset: &SaleKeyset,
    min_sat: u64,
    max_sat: u64,
) -> Result<Vec<BlindedMessage>, String> {
    check_sat(request.sat, min_sat, max_sat)?;
    if request.outputs.is_empty() || request.outputs.len() > MAX_OUTPUTS {
        return Err(format!("outputs must have 1 to {MAX_OUTPUTS} entries"));
    }
    let active = keyset.id.to_string();
    let mut outputs = Vec::with_capacity(request.outputs.len());
    let mut sum: u64 = 0;
    for (i, output) in request.outputs.iter().enumerate() {
        if output.id != active {
            return Err(format!(
                "output {i}: id {} is not the active sat keyset {active}",
                output.id
            ));
        }
        if !output.amount.is_power_of_two() || !keyset.amounts.contains(&output.amount) {
            return Err(format!(
                "output {i}: amount {} is not a power of two the keyset signs",
                output.amount
            ));
        }
        outputs.push(blinded(output).map_err(|e| format!("output {i}: {e}"))?);
        sum = sum.saturating_add(output.amount);
    }
    if sum != request.sat {
        return Err(format!(
            "output amounts sum to {sum}, not sat {}",
            request.sat
        ));
    }
    let mut points: Vec<&str> = request
        .outputs
        .iter()
        .map(|o| o.blinded_secret.as_str())
        .collect();
    points.sort_unstable();
    if points.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err("a B_ appears twice".into());
    }
    Ok(outputs)
}

/// `sat` within the configured limits (the first rule of [`check`]).
pub fn check_sat(sat: u64, min_sat: u64, max_sat: u64) -> Result<(), String> {
    if sat < min_sat || sat > max_sat {
        return Err(format!("sat must be between {min_sat} and {max_sat}"));
    }
    Ok(())
}

/// The outputs of a request [`check`] accepted when it was first paid,
/// without checking them against today's keyset (a retry must still find
/// what the mint signed before a keyset rotation).
pub fn blinded_messages(request: &EcashRequest) -> Result<Vec<BlindedMessage>, String> {
    request
        .outputs
        .iter()
        .enumerate()
        .map(|(i, output)| blinded(output).map_err(|e| format!("output {i}: {e}")))
        .collect()
}

fn blinded(output: &RequestedOutput) -> Result<BlindedMessage, String> {
    let keyset_id =
        Id::from_str(&output.id).map_err(|_| format!("id {} is not a keyset id", output.id))?;
    if !is_lower_hex(&output.blinded_secret, 66) {
        return Err("B_ must be a compressed secp256k1 point, 66 lowercase hex".into());
    }
    let point = PublicKey::from_hex(&output.blinded_secret)
        .map_err(|_| "B_ is not a point on secp256k1".to_owned())?;
    Ok(BlindedMessage::new(
        Amount::from(output.amount),
        keyset_id,
        point,
    ))
}

/// Value of the inputs that pays for `sat` of outputs: `sat` plus the NUT-02
/// input fee, `ceil(count × input_fee_ppk / 1000)`, of those inputs
/// themselves, which are the keyset's split of that value. `None` when no
/// value pays for itself exactly (a fee step the split cannot meet).
pub fn input_total(sat: u64, keyset: &SaleKeyset) -> Option<u64> {
    let fee_of = |total: u64| -> Option<u64> {
        let count = keyset.split(total)?.len() as u64;
        Some(count.checked_mul(keyset.input_fee_ppk)?.div_ceil(1000))
    };
    // The fee's own parts add at most 64 to the split of `sat` (fees stay
    // below the largest denomination).
    let parts = keyset.split(sat)?.len() as u64;
    let max_fee = parts
        .checked_add(64)?
        .checked_mul(keyset.input_fee_ppk)?
        .div_ceil(1000);
    (0..=max_fee).find_map(|fee| {
        let total = sat.checked_add(fee)?;
        (fee_of(total)? == fee).then_some(total)
    })
}

/// Why a sale did not deliver signatures.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SellError {
    /// The wallet holds too little to pay for the sale.
    Float(String),
    /// The mint or the wallet could not be used; a later retry is safe.
    Unavailable(String),
    /// The swap reached the mint but its outcome is unknown; the inputs stay
    /// pending under the sale until a retry resolves them.
    Unknown(String),
    /// The mint refused the swap or answered it wrongly; retrying the same
    /// outputs fails the same way until the operator steps in.
    Rejected(String),
    /// The mint already holds these outputs (signed by an earlier swap, or in
    /// one still in flight); [`EcashSeller::restore`] returns the signatures
    /// once they exist.
    AlreadySigned,
}

impl std::fmt::Display for SellError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SellError::Float(m) => write!(f, "float exhausted: {m}"),
            SellError::Unavailable(m) => write!(f, "unavailable: {m}"),
            SellError::Unknown(m) => write!(f, "sale outcome unknown: {m}"),
            SellError::Rejected(m) => write!(f, "rejected by the mint: {m}"),
            SellError::AlreadySigned => write!(f, "the mint already holds these outputs"),
        }
    }
}

/// The mint side of a sale.
#[async_trait::async_trait]
pub trait EcashSeller: Send + Sync {
    /// The mint's active `sat` keyset.
    async fn keyset(&self) -> Result<SaleKeyset, SellError>;

    /// Unspent ecash the issuer holds at the mint, in sat (the float).
    async fn spendable(&self) -> Result<u64, SellError>;

    /// Sells `sat` into `outputs` (accepted by [`check`]): reserves inputs
    /// worth exactly `sat` plus their input fee under the sale key `sale`,
    /// swaps them into `outputs` at the mint, and returns the blind
    /// signatures in output order. Inputs an earlier attempt of the same
    /// sale left pending are settled first.
    async fn sell(
        &self,
        sale: &str,
        sat: u64,
        outputs: &[BlindedMessage],
    ) -> Result<Vec<BlindSignature>, SellError>;

    /// NUT-09: the mint's signatures on `outputs` in output order when it
    /// signed all of them, `None` when it signed none. The inputs the sale
    /// `sale` left pending are then settled against the mint: spent ones are
    /// marked spent, unspent ones go back to the wallet.
    async fn restore(
        &self,
        sale: &str,
        outputs: &[BlindedMessage],
    ) -> Result<Option<Vec<BlindSignature>>, SellError>;
}

/// The wallet operation a sale's inputs are reserved under, derived from the
/// sale key so that a retry, even after a restart, finds what an earlier
/// attempt left behind.
fn operation_id(sale: &str) -> Uuid {
    let digest = Sha256::new()
        .chain_update(SALE_OPERATION_DOMAIN)
        .chain_update(sale.as_bytes())
        .finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    uuid::Builder::from_custom_bytes(bytes).into_uuid()
}

/// One proof per part, from the active keyset; `None` when the wallet lacks
/// one of the denominations.
fn pick(unspent: &[Proof], parts: &[Amount], keyset_id: Id) -> Option<Proofs> {
    let mut pool: Vec<&Proof> = unspent
        .iter()
        .filter(|proof| proof.keyset_id == keyset_id)
        .collect();
    let mut picked = Vec::with_capacity(parts.len());
    for part in parts {
        let i = pool.iter().position(|proof| proof.amount == *part)?;
        picked.push(pool.swap_remove(i).clone());
    }
    Some(picked)
}

fn wallet_error(error: impl std::fmt::Display) -> SellError {
    SellError::Unavailable(format!("wallet: {error}"))
}

/// [`EcashSeller`] over the issuer's `cdk` wallet for the mint it sells from
/// (unit `sat`); the wallet shares its database with
/// [`crate::cashu::CdkSwapper`].
///
/// A sale's inputs are reserved in the wallet database under an operation id
/// derived from the sale, set pending while the swap is in flight, marked
/// spent once the mint signed, and released after a definitive refusal; an
/// unknown outcome leaves them pending until a retry settles them against
/// the mint. When the wallet does not hold the exact denominations, one
/// ordinary wallet swap makes change first (a `cdk` swap saga, recovered at
/// startup like any other).
pub struct CdkSeller {
    wallet: Wallet,
    timeout: Duration,
}

impl CdkSeller {
    pub fn new(wallet: Wallet, timeout: Duration) -> Self {
        Self { wallet, timeout }
    }

    /// One call that may reach the mint, under the timeout.
    async fn at_mint<T>(
        &self,
        what: &str,
        call: impl Future<Output = Result<T, cdk::Error>>,
    ) -> Result<Result<T, cdk::Error>, String> {
        tokio::time::timeout(self.timeout, call)
            .await
            .map_err(|_| format!("{what}: no answer from the mint within {:?}", self.timeout))
    }

    /// Inputs of the sale still reserved or pending in the wallet.
    async fn held(&self, op: &Uuid) -> Result<Proofs, SellError> {
        Ok(self
            .wallet
            .localstore
            .get_reserved_proofs(op)
            .await
            .map_err(wallet_error)?
            .into_iter()
            .filter(|info| matches!(info.state, State::Reserved | State::Pending))
            .map(|info| info.proof)
            .collect())
    }

    /// Settles what an earlier attempt of the sale left behind against the
    /// mint (NUT-07): spent inputs are marked spent, the rest go back to the
    /// wallet. Inputs still pending at the mint leave the sale unresolved.
    async fn settle_held(&self, op: &Uuid) -> Result<(), SellError> {
        let held = self.held(op).await?;
        if held.is_empty() {
            return Ok(());
        }
        let ys = held.ys().map_err(wallet_error)?;
        let mint = self.wallet.mint_connector();
        let check_state = mint.post_check_state(CheckStateRequest { ys });
        let states = match self.at_mint("checkstate", check_state).await {
            Ok(Ok(response)) => response.states,
            Ok(Err(e)) => return Err(SellError::Unavailable(format!("checkstate: {e}"))),
            Err(message) => return Err(SellError::Unavailable(message)),
        };
        if states.iter().any(|s| s.state == State::Pending) {
            return Err(SellError::Unknown(
                "inputs of an earlier attempt are still pending at the mint".into(),
            ));
        }
        let spent: Vec<PublicKey> = states
            .iter()
            .filter(|s| s.state == State::Spent)
            .map(|s| s.y)
            .collect();
        if !spent.is_empty() {
            self.wallet
                .localstore
                .update_proofs_state(spent, State::Spent)
                .await
                .map_err(wallet_error)?;
        }
        self.wallet
            .localstore
            .release_proofs(op)
            .await
            .map_err(wallet_error)
    }

    /// Reserves inputs worth exactly `total`, the keyset's split of it, under
    /// `op`; makes change first when the wallet lacks a denomination.
    async fn reserve(
        &self,
        op: &Uuid,
        total: u64,
        keyset: &SaleKeyset,
    ) -> Result<Proofs, SellError> {
        let parts = keyset.split(total).ok_or_else(|| {
            SellError::Rejected(format!("{total} sat cannot be split in the keyset"))
        })?;
        let mut made_change = false;
        loop {
            let unspent = self
                .wallet
                .get_unspent_proofs()
                .await
                .map_err(wallet_error)?;
            if let Some(inputs) = pick(&unspent, &parts, keyset.id) {
                let ys = inputs.ys().map_err(wallet_error)?;
                self.wallet
                    .localstore
                    .reserve_proofs(ys, op)
                    .await
                    .map_err(wallet_error)?;
                return Ok(inputs);
            }
            if made_change {
                return Err(SellError::Unavailable(
                    "the wallet lacks the sale's denominations after making change".into(),
                ));
            }
            self.make_change(unspent, &parts, total, keyset).await?;
            made_change = true;
        }
    }

    /// One wallet swap that turns enough unspent proofs into `parts` (worth
    /// `total`); the rest of their value comes back as change.
    async fn make_change(
        &self,
        unspent: Proofs,
        parts: &[Amount],
        total: u64,
        keyset: &SaleKeyset,
    ) -> Result<(), SellError> {
        let fees = self
            .wallet
            .get_keyset_fees_and_amounts()
            .await
            .map_err(wallet_error)?;
        let active = vec![keyset.id];
        let inputs = Wallet::select_proofs(Amount::from(total), unspent, &active, &fees, true)
            .map_err(|e| match e {
                cdk::Error::InsufficientFunds => {
                    SellError::Float(format!("the wallet cannot cover {total} sat"))
                }
                e => wallet_error(e),
            })?;
        let swap = self.wallet.swap(
            None,
            SplitTarget::Values(parts.to_vec()),
            inputs,
            None,
            false,
            false,
        );
        match self.at_mint("making change", swap).await {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(cdk::Error::InsufficientFunds)) => Err(SellError::Float(format!(
                "the wallet cannot cover {total} sat and the change fee"
            ))),
            Ok(Err(e)) => Err(SellError::Unavailable(format!("making change: {e}"))),
            Err(message) => Err(SellError::Unavailable(message)),
        }
    }

    /// The checks a `cdk` wallet runs on its own swap answers: one signature
    /// per output, same amount and keyset, and a valid DLEQ proof when the
    /// mint sent one.
    async fn check_signatures(
        &self,
        signatures: &[BlindSignature],
        outputs: &[BlindedMessage],
    ) -> Result<(), String> {
        if signatures.len() != outputs.len() {
            return Err(format!(
                "the mint answered {} signatures for {} outputs",
                signatures.len(),
                outputs.len()
            ));
        }
        let Some(first) = outputs.first() else {
            return Ok(());
        };
        let keys = self
            .wallet
            .keyset(first.keyset_id)
            .await
            .map_err(|e| format!("keyset {}: {e}", first.keyset_id))?
            .keys;
        for (i, (signature, output)) in signatures.iter().zip(outputs).enumerate() {
            if signature.amount != output.amount || signature.keyset_id != output.keyset_id {
                return Err(format!("signature {i} does not match its output"));
            }
            let key = keys
                .amount_key(signature.amount)
                .ok_or_else(|| format!("signature {i}: no key for its amount"))?;
            match signature.verify_dleq(key, output.blinded_secret) {
                Ok(()) | Err(nut12::Error::MissingDleqProof) => {}
                Err(_) => return Err(format!("signature {i}: DLEQ proof does not verify")),
            }
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl EcashSeller for CdkSeller {
    async fn keyset(&self) -> Result<SaleKeyset, SellError> {
        let keyset = match self.at_mint("keyset", self.wallet.active_keyset()).await {
            Ok(Ok(keyset)) => keyset,
            Ok(Err(e)) => return Err(SellError::Unavailable(format!("keyset: {e}"))),
            Err(message) => return Err(SellError::Unavailable(message)),
        };
        Ok(SaleKeyset {
            id: keyset.id,
            amounts: keyset
                .keys
                .iter()
                .map(|(amount, _)| amount.to_u64())
                .collect(),
            input_fee_ppk: keyset.input_fee_ppk,
        })
    }

    async fn spendable(&self) -> Result<u64, SellError> {
        self.wallet
            .total_balance()
            .await
            .map(|amount| amount.to_u64())
            .map_err(wallet_error)
    }

    async fn sell(
        &self,
        sale: &str,
        sat: u64,
        outputs: &[BlindedMessage],
    ) -> Result<Vec<BlindSignature>, SellError> {
        let op = operation_id(sale);
        let keyset = self.keyset().await?;
        let total = input_total(sat, &keyset).ok_or_else(|| {
            SellError::Rejected(format!(
                "{sat} sat cannot be paid with exact inputs at input_fee_ppk {}",
                keyset.input_fee_ppk
            ))
        })?;
        self.settle_held(&op).await?;
        let mut replaced = false;
        loop {
            let inputs = self.reserve(&op, total, &keyset).await?;
            let ys = inputs.ys().map_err(wallet_error)?;
            self.wallet
                .localstore
                .update_proofs_state(ys.clone(), State::Pending)
                .await
                .map_err(wallet_error)?;
            let mint = self.wallet.mint_connector();
            let swap = mint.post_swap(SwapRequest::new(inputs, outputs.to_vec()));
            let error = match self.at_mint("swap", swap).await {
                Ok(Ok(response)) => {
                    // The mint took the inputs; they are spent whatever it
                    // answered.
                    let checked = self.check_signatures(&response.signatures, outputs).await;
                    self.wallet
                        .localstore
                        .update_proofs_state(ys, State::Spent)
                        .await
                        .map_err(|e| SellError::Unknown(format!("wallet: {e}")))?;
                    checked.map_err(SellError::Rejected)?;
                    return Ok(response.signatures);
                }
                Ok(Err(error)) => error,
                Err(message) => return Err(SellError::Unknown(message)),
            };
            match error {
                cdk::Error::TokenAlreadySpent => {
                    // The wallet believed these unspent: drop the spent ones
                    // and replace them once.
                    self.settle_held(&op).await?;
                    if replaced {
                        return Err(SellError::Unavailable(
                            "the mint reports the replacement inputs spent too".into(),
                        ));
                    }
                    replaced = true;
                }
                // cdk mints answer `DuplicateOutputs` for outputs they already
                // hold, signed or in flight.
                cdk::Error::BlindedMessageAlreadySigned | cdk::Error::DuplicateOutputs => {
                    self.wallet
                        .localstore
                        .release_proofs(&op)
                        .await
                        .map_err(wallet_error)?;
                    return Err(SellError::AlreadySigned);
                }
                error if error.is_definitive_failure() => {
                    self.wallet
                        .localstore
                        .release_proofs(&op)
                        .await
                        .map_err(wallet_error)?;
                    return Err(SellError::Rejected(error.to_string()));
                }
                error => return Err(SellError::Unknown(error.to_string())),
            }
        }
    }

    async fn restore(
        &self,
        sale: &str,
        outputs: &[BlindedMessage],
    ) -> Result<Option<Vec<BlindSignature>>, SellError> {
        let mint = self.wallet.mint_connector();
        let restore = mint.post_restore(RestoreRequest {
            outputs: outputs.to_vec(),
        });
        let response = match self.at_mint("restore", restore).await {
            Ok(Ok(response)) => response,
            Ok(Err(e)) => return Err(SellError::Unavailable(format!("restore: {e}"))),
            Err(message) => return Err(SellError::Unavailable(message)),
        };
        // The mint answers the outputs it has signed, each with its signature.
        let mut signatures = Vec::with_capacity(outputs.len());
        for output in outputs {
            if let Some(j) = response
                .outputs
                .iter()
                .position(|o| o.blinded_secret == output.blinded_secret)
            {
                let signature = response.signatures.get(j).ok_or_else(|| {
                    SellError::Unknown("restore answer has fewer signatures than outputs".into())
                })?;
                signatures.push(signature.clone());
            }
        }
        if signatures.is_empty() {
            return Ok(None);
        }
        if signatures.len() != outputs.len() {
            return Err(SellError::Unknown(format!(
                "the mint signed {} of {} outputs",
                signatures.len(),
                outputs.len()
            )));
        }
        self.check_signatures(&signatures, outputs)
            .await
            .map_err(SellError::Rejected)?;
        self.settle_held(&operation_id(sale)).await?;
        Ok(Some(signatures))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cdk::nuts::{BlindSignatureDleq, SecretKey};

    fn keyset(max_power: u32, input_fee_ppk: u64) -> SaleKeyset {
        SaleKeyset {
            id: Id::from_str("009a1f293253e41e").unwrap(),
            amounts: (0..=max_power).map(|i| 1u64 << i).collect(),
            input_fee_ppk,
        }
    }

    fn point(n: u8) -> String {
        SecretKey::from_slice(&[n; 32])
            .unwrap()
            .public_key()
            .to_hex()
    }

    fn request(sat: u64, outputs: &[(u64, u8)]) -> EcashRequest {
        EcashRequest {
            sat,
            outputs: outputs
                .iter()
                .map(|(amount, n)| RequestedOutput {
                    amount: *amount,
                    id: "009a1f293253e41e".into(),
                    blinded_secret: point(*n),
                })
                .collect(),
        }
    }

    fn refused(request: &EcashRequest) -> String {
        check(request, &keyset(31, 0), 10, 20_000).unwrap_err()
    }

    #[test]
    fn accepts_outputs_and_keeps_their_order() {
        let r = request(10, &[(2, 1), (8, 2)]);
        let outputs = check(&r, &keyset(31, 0), 10, 20_000).unwrap();
        assert_eq!(outputs.len(), 2);
        assert_eq!(outputs[0].amount, Amount::from(2));
        assert_eq!(outputs[1].amount, Amount::from(8));
        assert_eq!(outputs[1].blinded_secret.to_hex(), point(2));
        assert_eq!(outputs[0].keyset_id.to_string(), "009a1f293253e41e");
        assert!(outputs[0].witness.is_none());
        assert_eq!(blinded_messages(&r).unwrap(), outputs);
    }

    #[test]
    fn refuses_amounts_outside_the_limits_and_wrong_sums() {
        assert!(refused(&request(8, &[(8, 1)])).contains("between 10 and 20000"));
        assert!(refused(&request(32_768, &[(32_768, 1)])).contains("between"));
        assert!(refused(&request(10, &[(8, 1), (4, 2)])).contains("sum to 12"));
        assert!(refused(&request(12, &[(8, 1), (3, 2), (1, 3)])).contains("power of two"));
        // A power of two the keyset has no key for.
        let r = request(2048, &[(2048, 1)]);
        assert!(check(&r, &keyset(10, 0), 10, 20_000)
            .unwrap_err()
            .contains("output 0: amount 2048"));
        // Sums that overflow do not wrap around to `sat`.
        let r = request(16, &[(1 << 63, 1), (1 << 63, 2), (16, 3)]);
        assert!(check(&r, &keyset(63, 0), 10, 20_000)
            .unwrap_err()
            .contains("sum to"));
    }

    #[test]
    fn refuses_bad_output_counts_keysets_and_points() {
        assert!(refused(&request(10, &[])).contains("1 to 256"));
        let many: Vec<(u64, u8)> = (0..257).map(|i| (1, (i % 250) as u8 + 1)).collect();
        assert!(refused(&request(257, &many)).contains("1 to 256"));

        let mut other = request(10, &[(8, 1), (2, 2)]);
        other.outputs[1].id = "00ffd48b8f5ecf80".into();
        assert!(refused(&other).contains("output 1: id 00ffd48b8f5ecf80 is not the active"));
        let mut upper = request(10, &[(8, 1), (2, 2)]);
        upper.outputs[0].id = "009A1F293253E41E".into();
        assert!(refused(&upper).contains("not the active"));

        let mut upper_point = request(10, &[(8, 1), (2, 2)]);
        upper_point.outputs[0].blinded_secret = point(1).to_uppercase();
        assert!(refused(&upper_point).contains("66 lowercase hex"));
        let mut off_curve = request(10, &[(8, 1), (2, 2)]);
        off_curve.outputs[1].blinded_secret = format!("02{}", "ff".repeat(32));
        assert!(refused(&off_curve).contains("output 1: B_ is not a point"));
        let mut uncompressed = request(10, &[(8, 1), (2, 2)]);
        uncompressed.outputs[0].blinded_secret = format!("04{}", "11".repeat(64));
        assert!(refused(&uncompressed).contains("compressed"));

        assert!(refused(&request(16, &[(8, 1), (8, 1)])).contains("appears twice"));
    }

    #[test]
    fn inputs_pay_for_the_outputs_and_their_own_fee() {
        assert_eq!(input_total(1000, &keyset(31, 0)), Some(1000));
        // 1001 = 512+256+128+64+32+8+1: seven inputs at 100 ppk cost 1 sat.
        assert_eq!(input_total(1000, &keyset(31, 100)), Some(1001));
        // At 1000 ppk: 10 → 8+2 costs 2, 12 → 8+4 costs 2.
        assert_eq!(input_total(10, &keyset(31, 1000)), Some(12));
        // Only 1-sat proofs at one sat each: every extra input costs itself.
        assert_eq!(input_total(5, &keyset(0, 1000)), None);
    }

    #[test]
    fn sale_operations_are_stable_per_sale() {
        let a = operation_id("lnbtc:000000000019d6689c085ae165831e93:aa");
        assert_eq!(a, operation_id("lnbtc:000000000019d6689c085ae165831e93:aa"));
        assert_ne!(a, operation_id("lnbtc:000000000019d6689c085ae165831e93:ab"));
        assert_eq!(a.get_version_num(), 8);
    }

    #[test]
    fn signatures_serialize_as_nut00_with_nut12_dleq() {
        let k = SecretKey::from_slice(&[7; 32]).unwrap();
        let blinded = PublicKey::from_hex(point(3)).unwrap();
        let c = cdk::dhke::sign_message(&k, &blinded).unwrap();
        let mut signature = BlindSignature {
            amount: Amount::from(8),
            keyset_id: Id::from_str("009a1f293253e41e").unwrap(),
            c,
            dleq: Some(BlindSignatureDleq {
                e: SecretKey::from_slice(&[1; 32]).unwrap(),
                s: SecretKey::from_slice(&[2; 32]).unwrap(),
            }),
        };
        let value = serde_json::to_value(EcashSignature::from(&signature)).unwrap();
        assert_eq!(
            value,
            serde_json::json!({
                "amount": 8,
                "id": "009a1f293253e41e",
                "C_": c.to_hex(),
                "dleq": {"e": "01".repeat(32), "s": "02".repeat(32)},
            })
        );
        // The wire form is the NUT-00 one: cdk reads it back unchanged.
        let parsed: BlindSignature = serde_json::from_value(value).unwrap();
        assert_eq!(parsed, signature);
        signature.dleq = None;
        let value = serde_json::to_value(EcashSignature::from(&signature)).unwrap();
        assert!(value.get("dleq").is_none());
    }
}
