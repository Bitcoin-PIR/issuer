//! Cashu side: offline token inspection, the idempotency key, and the swap
//! (receive) at the mint through the `cdk` wallet.
//!
//! Only [`TokenSummary::parse`] and [`token_key`] run on the request path
//! before anything touches the network; the [`Swapper`] trait isolates the
//! mint round-trip so the HTTP layer is tested with a fake.

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;

use cdk::nuts::{CurrencyUnit, Token};
use cdk::wallet::{ReceiveOptions, Wallet};
use sha2::{Digest, Sha256};

/// Domain separator for the idempotency key, so the same secrets used in any
/// other protocol never collide with a issuer key.
// Historical tag from the cashier era: it keys the persisted swap ledger, so
// renaming the service must not change it.
const TOKEN_KEY_DOMAIN: &[u8] = b"BPIR-CASHIER-TOKEN-KEY-V1";

/// What a token claims about itself, read without contacting the mint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenSummary {
    /// Mint URL exactly as encoded (no trailing slash).
    pub mint: String,
    /// Currency unit as its canonical string (`sat`, `usd`, …).
    pub unit: String,
    /// Sum of the proof amounts (face value; mints may deduct input fees).
    pub amount: u64,
    /// Proof secrets, sorted and deduplicated.
    pub secrets: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum TokenParseError {
    #[error("token is not a Cashu token: {0}")]
    Malformed(String),
    #[error("token has no proofs")]
    Empty,
    #[error("token carries no unit")]
    NoUnit,
    #[error("token spans several mints")]
    MultiMint,
}

impl TokenSummary {
    /// Decode a `cashuA…`/`cashuB…` token and summarize it.
    pub fn parse(encoded: &str) -> Result<Self, TokenParseError> {
        let token = Token::from_str(encoded.trim())
            .map_err(|e| TokenParseError::Malformed(e.to_string()))?;
        let mint = token
            .mint_url()
            .map_err(|_| TokenParseError::MultiMint)?
            .to_string();
        let unit = token.unit().ok_or(TokenParseError::NoUnit)?.to_string();
        let amount = token
            .value()
            .map_err(|e| TokenParseError::Malformed(e.to_string()))?
            .to_u64();
        let mut secrets: Vec<String> = match &token {
            Token::TokenV3(t) => t
                .token
                .iter()
                .flat_map(|entry| entry.proofs.iter().map(|p| p.secret.to_string()))
                .collect(),
            Token::TokenV4(t) => t
                .token
                .iter()
                .flat_map(|entry| entry.proofs.iter().map(|p| p.secret.to_string()))
                .collect(),
        };
        if secrets.is_empty() {
            return Err(TokenParseError::Empty);
        }
        secrets.sort();
        secrets.dedup();
        Ok(Self {
            mint: mint.trim_end_matches('/').to_string(),
            unit,
            amount,
            secrets,
        })
    }
}

/// Idempotency key: SHA-256 over the domain tag and the sorted secrets, each
/// prefixed by its byte length so no two secret lists share an encoding.
pub fn token_key(secrets: &[String]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(TOKEN_KEY_DOMAIN);
    hasher.update((secrets.len() as u64).to_le_bytes());
    for secret in secrets {
        hasher.update((secret.len() as u64).to_le_bytes());
        hasher.update(secret.as_bytes());
    }
    hasher.finalize().into()
}

/// Why a swap did not produce money in the issuer's wallet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SwapError {
    /// The mint refused the token (already spent, bad signature, unknown
    /// keyset, …). The token is worthless; answer 402.
    Rejected(String),
    /// The mint could not be reached or answered with a server error before
    /// accepting anything. The token is still spendable; answer 503.
    Unavailable(String),
    /// The request reached the mint but the outcome is unknown (timeout after
    /// sending). The token may or may not be spent; answer 503 and keep the
    /// `pending` marker so a retry is reported honestly.
    Unknown(String),
}

impl std::fmt::Display for SwapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SwapError::Rejected(m) => write!(f, "rejected by the mint: {m}"),
            SwapError::Unavailable(m) => write!(f, "mint unavailable: {m}"),
            SwapError::Unknown(m) => write!(f, "swap outcome unknown: {m}"),
        }
    }
}

/// Swap (receive) a token so the issuer owns its value. Returns the amount
/// the mint credited, in the token's unit.
#[async_trait::async_trait]
pub trait Swapper: Send + Sync {
    async fn receive(&self, summary: &TokenSummary, encoded_token: &str) -> Result<u64, SwapError>;
}

/// One `cdk` wallet per accepted (mint, unit), all sharing a SQLite store.
pub struct CdkSwapper {
    wallets: HashMap<(String, String), Wallet>,
    timeout: std::time::Duration,
}

impl CdkSwapper {
    /// Open the wallet database and create a wallet for every (mint, unit)
    /// pair the configuration sells in.
    pub async fn open(
        db_path: &std::path::Path,
        seed: [u8; 64],
        mints: &[String],
        units: &[String],
        timeout: std::time::Duration,
    ) -> anyhow::Result<Self> {
        let db = cdk_sqlite::WalletSqliteDatabase::new(db_path.to_path_buf())
            .await
            .map_err(|e| anyhow::anyhow!("open wallet database {}: {e}", db_path.display()))?;
        let localstore: Arc<
            dyn cdk::cdk_database::WalletDatabase<cdk::cdk_database::Error> + Send + Sync,
        > = Arc::new(db);
        let mut wallets = HashMap::new();
        for mint in mints {
            for unit in units {
                let currency = CurrencyUnit::from_str(unit)
                    .map_err(|e| anyhow::anyhow!("unit {unit}: {e}"))?;
                let wallet = Wallet::new(mint, currency, Arc::clone(&localstore), seed, None)
                    .map_err(|e| anyhow::anyhow!("wallet for {mint} ({unit}): {e}"))?;
                wallets.insert(
                    (mint.trim_end_matches('/').to_string(), unit.clone()),
                    wallet,
                );
            }
        }
        Ok(Self { wallets, timeout })
    }

    /// Total proofs held per (mint, unit), for the operator's `balance` command.
    pub async fn balances(&self) -> Vec<((String, String), Result<u64, String>)> {
        let mut out = Vec::new();
        for (key, wallet) in &self.wallets {
            let balance = wallet
                .total_balance()
                .await
                .map(|a| a.to_u64())
                .map_err(|e| e.to_string());
            out.push((key.clone(), balance));
        }
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }
}

fn classify(error: cdk::Error) -> SwapError {
    use cdk::Error as E;
    match &error {
        E::TokenAlreadySpent | E::TokenPending => SwapError::Rejected(error.to_string()),
        E::HttpError(None, msg) => SwapError::Unavailable(msg.clone()),
        E::HttpError(Some(status), msg) if *status >= 500 => {
            SwapError::Unavailable(format!("mint answered {status}: {msg}"))
        }
        _ if error.is_definitive_failure() => SwapError::Rejected(error.to_string()),
        _ => SwapError::Rejected(error.to_string()),
    }
}

#[async_trait::async_trait]
impl Swapper for CdkSwapper {
    async fn receive(&self, summary: &TokenSummary, encoded_token: &str) -> Result<u64, SwapError> {
        let wallet = self
            .wallets
            .get(&(summary.mint.clone(), summary.unit.clone()))
            .ok_or_else(|| {
                SwapError::Rejected(format!("no wallet for {} ({})", summary.mint, summary.unit))
            })?;
        match tokio::time::timeout(
            self.timeout,
            wallet.receive(encoded_token, ReceiveOptions::default()),
        )
        .await
        {
            Ok(Ok(amount)) => Ok(amount.to_u64()),
            Ok(Err(error)) => Err(classify(error)),
            Err(_elapsed) => Err(SwapError::Unknown(format!(
                "no answer from the mint within {:?}",
                self.timeout
            ))),
        }
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use cdk::mint_url::MintUrl;
    use cdk::nuts::{Id, Proof, PublicKey};
    use cdk::secret::Secret;
    use cdk::Amount;

    /// Build an encoded V4 token with `amounts` proofs at `mint` in `unit`.
    /// The proofs carry syntactically valid but unsigned data; enough for
    /// parsing, never for a real mint.
    pub fn fake_token(mint: &str, unit: &str, amounts: &[u64]) -> String {
        let keyset = Id::from_str("00ffd48b8f5ecf80").unwrap();
        let c = PublicKey::from_hex(
            "02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2",
        )
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_reads_mint_unit_value_and_sorted_secrets() {
        let encoded = test_support::fake_token("https://mint.example", "sat", &[128, 64, 16, 2]);
        assert!(encoded.starts_with("cashuB"));
        let s = TokenSummary::parse(&encoded).unwrap();
        assert_eq!(s.mint, "https://mint.example");
        assert_eq!(s.unit, "sat");
        assert_eq!(s.amount, 210);
        assert_eq!(s.secrets.len(), 4);
        let mut sorted = s.secrets.clone();
        sorted.sort();
        assert_eq!(s.secrets, sorted);
    }

    #[test]
    fn garbage_is_rejected() {
        assert!(matches!(
            TokenSummary::parse("cashuBnope"),
            Err(TokenParseError::Malformed(_))
        ));
        assert!(matches!(
            TokenSummary::parse(""),
            Err(TokenParseError::Malformed(_))
        ));
    }

    #[test]
    fn token_key_is_stable_and_order_independent() {
        let a = token_key(&["x".into(), "y".into()]);
        let b = token_key(&["x".into(), "y".into()]);
        assert_eq!(a, b);
        assert_ne!(a, token_key(&["x".into()]));
        assert_ne!(
            token_key(&["ab".into(), "c".into()]),
            token_key(&["a".into(), "bc".into()])
        );
    }
}
