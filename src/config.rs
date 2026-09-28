//! TOML configuration. Everything an operator decides lives here; nothing is
//! hard-coded in the binary except the contract itself.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Socket the HTTP server binds. Put a reverse proxy or a Cloudflare
    /// tunnel in front; the issuer speaks plain HTTP.
    pub listen: SocketAddr,
    /// 32-byte Ed25519 issuer seed (raw, or 64 hex characters) that signs
    /// every `POST /v2/redeem` answer. The PIR servers pin the matching
    /// public key (`--credit-issuer-pubkey`). The name predates credits.
    pub grant_key_path: PathBuf,
    /// 64-byte seed (raw, or 128 hex characters) for the Cashu wallet keys.
    pub wallet_seed_path: PathBuf,
    /// SQLite file the Cashu wallet keeps its proofs in.
    pub wallet_db_path: PathBuf,
    /// Append-only JSON-lines file recording every token seen and what it
    /// bought (idempotency and operator reconciliation).
    pub store_path: PathBuf,
    /// Mints whose ecash is accepted (https only).
    pub mints: Vec<String>,
    /// Browser origins allowed by CORS. Empty means any origin, which is
    /// safe because the API uses no cookies and no ambient credentials.
    #[serde(default)]
    pub cors_origins: Vec<String>,
    /// Credits contract parameters published in `GET /v2/info` and used to
    /// turn redeemed sats into gas (`docs/CREDITS.md`).
    #[serde(default)]
    pub gas: GasConfig,
    /// Operator identity keys (64 hex) whose certified servers may redeem
    /// here. Empty keeps `POST /v2/redeem` refused.
    #[serde(default)]
    pub operator_pubkeys: Vec<String>,
    /// Tolerated difference between a redeem request's clock and ours.
    #[serde(default = "default_redeem_skew")]
    pub redeem_max_skew_secs: u64,
    /// Append-only JSON-lines log of every redemption (replay index and
    /// settlement ledger). Defaults to `redeem.jsonl` next to `store_path`.
    #[serde(default)]
    pub redeem_store_path: Option<PathBuf>,
    /// Worst-case prices published in `GET /v2/info` as `rate_card`
    /// (informational; the servers meter gas).
    #[serde(default = "default_rate_card")]
    pub rate_card: Vec<RateCardEntry>,
    /// ARC credentials (`docs/CREDITS.md`). Absent keeps `POST /v2/credentials`
    /// and ARC items of `POST /v2/redeem` refused.
    #[serde(default)]
    pub arc: Option<ArcConfig>,
}

/// The `[arc]` table.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArcConfig {
    /// 32-byte master seed (raw, or 64 hex characters) from
    /// `bpir-issuer arc-seed`; every epoch's issuer keys derive from it.
    pub seed_path: PathBuf,
    #[serde(default = "default_arc_epoch_secs")]
    pub epoch_secs: u64,
    #[serde(default = "default_arc_grace_secs")]
    pub grace_secs: u64,
    /// Presentations per credential (one credit each).
    #[serde(default = "default_arc_limit")]
    pub presentation_limit: u32,
    /// Packs on sale at `POST /v2/credentials`; `credits` must equal
    /// `presentation_limit` (one credential per pack).
    #[serde(default = "default_credential_offers")]
    pub credential_offers: Vec<CredentialOffer>,
}

/// One `[[arc.credential_offers]]` line.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialOffer {
    pub credits: u64,
    pub sat: u64,
}

fn default_arc_epoch_secs() -> u64 {
    pir_credit::arc::ARC_EPOCH_SECS
}

fn default_arc_grace_secs() -> u64 {
    pir_credit::arc::ARC_GRACE_SECS
}

fn default_arc_limit() -> u32 {
    pir_credit::arc::ARC_PRESENTATION_LIMIT
}

fn default_credential_offers() -> Vec<CredentialOffer> {
    vec![CredentialOffer {
        credits: u64::from(pir_credit::arc::ARC_PRESENTATION_LIMIT),
        sat: u64::from(pir_credit::arc::ARC_PRESENTATION_LIMIT)
            * pir_credit::GasParams::PRODUCTION_2026_09.credit_sat,
    }]
}

/// The `[gas]` table: `pir_credit::GasParams` with the 2026-09 defaults.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GasConfig {
    #[serde(default = "default_credit_sat")]
    pub credit_sat: u64,
    #[serde(default = "default_gas_per_credit")]
    pub gas_per_credit: u64,
    #[serde(default = "default_base_gas_per_frame")]
    pub base_gas_per_frame: u64,
    #[serde(default = "default_egress_gas_per_mb")]
    pub egress_gas_per_mb: u64,
}

impl GasConfig {
    pub fn params(&self) -> pir_credit::GasParams {
        pir_credit::GasParams {
            credit_sat: self.credit_sat,
            gas_per_credit: self.gas_per_credit,
            base_gas_per_frame: self.base_gas_per_frame,
            egress_gas_per_mb: self.egress_gas_per_mb,
        }
    }
}

impl Default for GasConfig {
    fn default() -> Self {
        let p = pir_credit::GasParams::PRODUCTION_2026_09;
        Self {
            credit_sat: p.credit_sat,
            gas_per_credit: p.gas_per_credit,
            base_gas_per_frame: p.base_gas_per_frame,
            egress_gas_per_mb: p.egress_gas_per_mb,
        }
    }
}

fn default_credit_sat() -> u64 {
    pir_credit::GasParams::PRODUCTION_2026_09.credit_sat
}

fn default_gas_per_credit() -> u64 {
    pir_credit::GasParams::PRODUCTION_2026_09.gas_per_credit
}

fn default_base_gas_per_frame() -> u64 {
    pir_credit::GasParams::PRODUCTION_2026_09.base_gas_per_frame
}

fn default_egress_gas_per_mb() -> u64 {
    pir_credit::GasParams::PRODUCTION_2026_09.egress_gas_per_mb
}

fn default_redeem_skew() -> u64 {
    300
}

/// One `[[rate_card]]` line.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateCardEntry {
    pub flow: String,
    pub credits: u64,
}

fn default_rate_card() -> Vec<RateCardEntry> {
    [
        ("onion_single_address", 10),
        ("harmony_fresh_client", 5),
        ("dpf_single_address", 2),
        ("oram_single_address", 1),
    ]
    .into_iter()
    .map(|(flow, credits)| RateCardEntry {
        flow: flow.to_owned(),
        credits,
    })
    .collect()
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("read {0}: {1}")]
    Read(PathBuf, std::io::Error),
    #[error("parse {0}: {1}")]
    Parse(PathBuf, toml::de::Error),
    #[error("{0}")]
    Invalid(String),
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text =
            std::fs::read_to_string(path).map_err(|e| ConfigError::Read(path.to_path_buf(), e))?;
        let config: Config =
            toml::from_str(&text).map_err(|e| ConfigError::Parse(path.to_path_buf(), e))?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.mints.is_empty() {
            return Err(ConfigError::Invalid(
                "mints must list at least one mint".into(),
            ));
        }
        for mint in &self.mints {
            if !mint.starts_with("https://") || mint.len() <= "https://".len() {
                return Err(ConfigError::Invalid(format!(
                    "mint is not an https URL: {mint}"
                )));
            }
            if mint.ends_with('/') {
                return Err(ConfigError::Invalid(format!(
                    "mint URL must not end with a slash (tokens carry it without one): {mint}"
                )));
            }
        }
        self.gas
            .params()
            .validate()
            .map_err(|e| ConfigError::Invalid(format!("gas: {e}")))?;
        for key in &self.operator_pubkeys {
            let bytes = hex::decode(key).map_err(|_| {
                ConfigError::Invalid(format!("operator_pubkeys: {key:?} is not hex"))
            })?;
            let bytes: [u8; 32] = bytes.try_into().map_err(|_| {
                ConfigError::Invalid(format!("operator_pubkeys: {key:?} is not 32 bytes"))
            })?;
            ed25519_dalek::VerifyingKey::from_bytes(&bytes).map_err(|_| {
                ConfigError::Invalid(format!("operator_pubkeys: {key:?} is not an Ed25519 key"))
            })?;
        }
        if self.redeem_max_skew_secs == 0 || self.redeem_max_skew_secs > 3600 {
            return Err(ConfigError::Invalid(
                "redeem_max_skew_secs must be 1..=3600".into(),
            ));
        }
        for entry in &self.rate_card {
            if entry.flow.is_empty() || entry.credits == 0 {
                return Err(ConfigError::Invalid(format!(
                    "rate_card entry has an empty field: {entry:?}"
                )));
            }
        }
        if let Some(arc) = &self.arc {
            if arc.epoch_secs < 86_400 {
                return Err(ConfigError::Invalid(
                    "arc.epoch_secs must be at least one day".into(),
                ));
            }
            if arc.grace_secs > arc.epoch_secs {
                return Err(ConfigError::Invalid(
                    "arc.grace_secs must not exceed arc.epoch_secs".into(),
                ));
            }
            if !(2..=4096).contains(&arc.presentation_limit) {
                return Err(ConfigError::Invalid(
                    "arc.presentation_limit must be 2..=4096".into(),
                ));
            }
            if arc.credential_offers.is_empty() {
                return Err(ConfigError::Invalid(
                    "arc.credential_offers must list at least one pack".into(),
                ));
            }
            for offer in &arc.credential_offers {
                if offer.credits != u64::from(arc.presentation_limit) || offer.sat == 0 {
                    return Err(ConfigError::Invalid(format!(
                        "arc credential offer must sell exactly {} credits for a positive price: {offer:?}",
                        arc.presentation_limit
                    )));
                }
            }
        }
        for origin in &self.cors_origins {
            if !(origin.starts_with("https://") || origin.starts_with("http://localhost")) {
                return Err(ConfigError::Invalid(format!(
                    "cors origin is not https: {origin}"
                )));
            }
        }
        Ok(())
    }

    pub fn accepts_mint(&self, mint: &str) -> bool {
        let normalized = mint.trim_end_matches('/');
        self.mints.iter().any(|m| m == normalized)
    }

    /// Parsed `operator_pubkeys` (validated by [`Config::validate`]).
    pub fn operator_keys(&self) -> Vec<ed25519_dalek::VerifyingKey> {
        self.operator_pubkeys
            .iter()
            .filter_map(|key| {
                let bytes: [u8; 32] = hex::decode(key).ok()?.try_into().ok()?;
                ed25519_dalek::VerifyingKey::from_bytes(&bytes).ok()
            })
            .collect()
    }

    /// `redeem_store_path`, or `redeem.jsonl` next to `store_path`.
    pub fn redeem_store_path(&self) -> PathBuf {
        self.redeem_store_path
            .clone()
            .unwrap_or_else(|| self.store_path.with_file_name("redeem.jsonl"))
    }
}

/// Read a secret seed file that holds either `len` raw bytes or `2*len` hex
/// characters (optionally newline-terminated), as `bpir-admin keygen` and
/// `head -c 64 /dev/urandom` produce.
pub fn read_seed_file(path: &Path, len: usize) -> Result<zeroize::Zeroizing<Vec<u8>>, String> {
    let raw = std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let raw = zeroize::Zeroizing::new(raw);
    if raw.len() == len {
        return Ok(raw);
    }
    let text = std::str::from_utf8(&raw).map_err(|_| {
        format!(
            "{} is neither {len} raw bytes nor {} hex characters",
            path.display(),
            2 * len
        )
    })?;
    let decoded = hex::decode(text.trim()).map_err(|_| {
        format!(
            "{} is neither {len} raw bytes nor {} hex characters",
            path.display(),
            2 * len
        )
    })?;
    if decoded.len() != len {
        return Err(format!(
            "{} decodes to {} bytes, expected {len}",
            path.display(),
            decoded.len()
        ));
    }
    Ok(zeroize::Zeroizing::new(decoded))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Config {
        toml::from_str(
            r#"
            listen = "127.0.0.1:8095"
            grant_key_path = "grant.key"
            wallet_seed_path = "wallet.seed"
            wallet_db_path = "wallet.sqlite"
            store_path = "grants.jsonl"
            mints = ["https://mint.example"]
            "#,
        )
        .unwrap()
    }

    #[test]
    fn sample_validates_with_defaults() {
        let c = sample();
        c.validate().unwrap();
        assert!(c.cors_origins.is_empty());
        assert!(c.accepts_mint("https://mint.example/"));
        assert!(!c.accepts_mint("https://other.example"));
    }

    #[test]
    fn retired_session_grant_keys_are_refused() {
        // A config from before the retirement fails loudly at startup
        // instead of silently selling nothing.
        for retired in [
            "grant_ttl_secs = 86400",
            "[costs]\nframe = 1",
            "[[offers]]\ncredits = 1\namount = 1\nunit = \"sat\"",
        ] {
            let text = format!(
                r#"
                listen = "127.0.0.1:8095"
                grant_key_path = "grant.key"
                wallet_seed_path = "wallet.seed"
                wallet_db_path = "wallet.sqlite"
                store_path = "grants.jsonl"
                mints = ["https://mint.example"]
                {retired}
                "#
            );
            assert!(toml::from_str::<Config>(&text).is_err(), "{retired}");
        }
    }

    #[test]
    fn rejects_bad_values() {
        let mut c = sample();
        c.mints = vec!["http://mint.example".into()];
        assert!(c.validate().is_err());
        let mut c = sample();
        c.mints = vec!["https://mint.example/".into()];
        assert!(c.validate().is_err());
    }

    #[test]
    fn seed_file_accepts_raw_and_hex() {
        let dir = tempfile::tempdir().unwrap();
        let raw = dir.path().join("raw");
        std::fs::write(&raw, [7u8; 32]).unwrap();
        assert_eq!(read_seed_file(&raw, 32).unwrap().as_slice(), &[7u8; 32]);
        let hexf = dir.path().join("hex");
        std::fs::write(&hexf, format!("{}\n", hex::encode([9u8; 32]))).unwrap();
        assert_eq!(read_seed_file(&hexf, 32).unwrap().as_slice(), &[9u8; 32]);
        assert!(read_seed_file(&hexf, 64).is_err());
    }
}
