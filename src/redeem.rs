//! `POST /v2/redeem` (docs/CREDITS.md "Issuer API"): a PIR server forwards
//! what a client presented; the issuer authenticates the server, verifies
//! and settles each item, books the value to the server's account, and
//! answers with a signed gas amount.
//!
//! Authentication of the server: its request carries an operator-signed
//! identity certificate whose operator key must be one the operator
//! configured (`operator_pubkeys`), and the request is signed by the
//! certificate's identity key. Replays are answered from the redeem store
//! (same `(server_id, nonce)`, same signed answer) without touching the
//! mint again.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use pir_credit::issuer::{RedeemRequestV1, RedeemResponseV1, REDEEM_NONCE_LEN};
use pir_identity::IdentityCert;
use serde::{Deserialize, Serialize};

use crate::api::ApiError;

/// A request whose signature chain checked out.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedRedeem {
    pub server_id: String,
    pub nonce: [u8; REDEEM_NONCE_LEN],
    pub nonce_hex: String,
    pub items: Vec<(u8, Vec<u8>)>,
}

/// Check the certificate against the configured operator keys, the
/// request signature against the certificate's identity key, the clock,
/// and the encodings. Nothing here touches the network or the stores.
pub fn verify_request(
    request: &RedeemRequestV1,
    operator_keys: &[VerifyingKey],
    now: u64,
    max_skew_secs: u64,
) -> Result<VerifiedRedeem, ApiError> {
    if operator_keys.is_empty() {
        return Err(ApiError::unauthorized(
            "this issuer accepts no server: operator_pubkeys is empty",
        ));
    }
    let cert_bytes = hex::decode(&request.identity_cert_hex)
        .map_err(|_| ApiError::invalid_request("identity_cert_hex is not hex"))?;
    let cert = IdentityCert::decode(&cert_bytes)
        .map_err(|e| ApiError::unauthorized(format!("identity certificate: {e}")))?;
    cert.verify()
        .map_err(|e| ApiError::unauthorized(format!("identity certificate: {e}")))?;
    if !operator_keys
        .iter()
        .any(|key| key.to_bytes() == cert.operator_pubkey)
    {
        return Err(ApiError::unauthorized(
            "identity certificate is signed by an operator this issuer does not serve",
        ));
    }
    if cert.server_id != request.server_id {
        return Err(ApiError::unauthorized(format!(
            "server_id {:?} does not match the certificate's {:?}",
            request.server_id, cert.server_id
        )));
    }
    let now_i64 = i64::try_from(now).unwrap_or(i64::MAX);
    if cert.valid_from > now_i64 || (cert.valid_until != 0 && cert.valid_until <= now_i64) {
        return Err(ApiError::unauthorized(
            "identity certificate is outside its validity window",
        ));
    }
    let skew = now.abs_diff(request.unix_time);
    if skew > max_skew_secs {
        return Err(ApiError::invalid_request(format!(
            "request time is {skew}s away from the issuer clock (limit {max_skew_secs}s)"
        )));
    }
    let nonce_bytes = hex::decode(&request.nonce_hex)
        .map_err(|_| ApiError::invalid_request("nonce_hex is not hex"))?;
    let nonce: [u8; REDEEM_NONCE_LEN] = nonce_bytes
        .try_into()
        .map_err(|_| ApiError::invalid_request("nonce must be 16 bytes"))?;
    if request.items.is_empty() {
        return Err(ApiError::invalid_request("no items to redeem"));
    }
    let mut items = Vec::with_capacity(request.items.len());
    for item in &request.items {
        let payload = hex::decode(&item.payload_hex)
            .map_err(|_| ApiError::invalid_request("item payload_hex is not hex"))?;
        if payload.is_empty() {
            return Err(ApiError::invalid_request("empty item payload"));
        }
        items.push((item.kind, payload));
    }
    let borrowed: Vec<(u8, &[u8])> = items
        .iter()
        .map(|(kind, payload)| (*kind, payload.as_slice()))
        .collect();
    let preimage =
        RedeemRequestV1::signing_preimage(&request.server_id, &nonce, request.unix_time, &borrowed);
    let signature = hex::decode(&request.signature_hex)
        .ok()
        .and_then(|bytes| Signature::from_slice(&bytes).ok())
        .ok_or_else(|| ApiError::unauthorized("request signature is malformed"))?;
    let identity_key = VerifyingKey::from_bytes(&cert.identity_pubkey)
        .map_err(|_| ApiError::unauthorized("identity certificate carries no valid key"))?;
    identity_key
        .verify(&preimage, &signature)
        .map_err(|_| ApiError::unauthorized("request signature does not verify"))?;
    Ok(VerifiedRedeem {
        server_id: request.server_id.clone(),
        nonce,
        nonce_hex: hex::encode(nonce),
        items,
    })
}

/// One settled redemption, as the append-only redeem log records it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedeemEvent {
    pub server_id: String,
    pub nonce_hex: String,
    pub unix_time: u64,
    pub gas_added: u64,
    pub sat_value: u64,
    pub items_accepted: u32,
    pub issuer_signature_hex: String,
    /// Epoch of the ARC presentations this redemption consumed, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epoch: Option<u32>,
    /// Tags of the ARC presentations consumed (the double-spend set).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags_hex: Vec<String>,
}

impl RedeemEvent {
    pub fn response(&self) -> RedeemResponseV1 {
        RedeemResponseV1 {
            gas_added: self.gas_added,
            sat_value: self.sat_value,
            items_accepted: self.items_accepted,
            issuer_signature_hex: self.issuer_signature_hex.clone(),
        }
    }
}

/// Per-server settlement totals.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ServerTotals {
    pub redemptions: u64,
    pub gas: u64,
    pub sat: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum RedeemStoreError {
    #[error("open {0}: {1}")]
    Open(PathBuf, std::io::Error),
    #[error("replay {0} line {1}: {2}")]
    Replay(PathBuf, usize, String),
    #[error("append: {0}")]
    Append(std::io::Error),
}

/// Append-only JSON-lines log of every redemption: the replay index for
/// `(server_id, nonce)` and the settlement ledger per server.
pub struct RedeemStore {
    path: PathBuf,
    file: File,
    answers: HashMap<(String, String), RedeemEvent>,
    totals: BTreeMap<String, ServerTotals>,
    seen_tags: HashSet<(u32, String)>,
}

impl RedeemStore {
    pub fn open(path: &Path) -> Result<Self, RedeemStoreError> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .open(path)
            .map_err(|e| RedeemStoreError::Open(path.to_path_buf(), e))?;
        let mut store = Self {
            path: path.to_path_buf(),
            file,
            answers: HashMap::new(),
            totals: BTreeMap::new(),
            seen_tags: HashSet::new(),
        };
        let reader = BufReader::new(
            File::open(path).map_err(|e| RedeemStoreError::Open(path.to_path_buf(), e))?,
        );
        for (n, line) in reader.lines().enumerate() {
            let line = line
                .map_err(|e| RedeemStoreError::Replay(path.to_path_buf(), n + 1, e.to_string()))?;
            if line.trim().is_empty() {
                continue;
            }
            let event: RedeemEvent = serde_json::from_str(&line)
                .map_err(|e| RedeemStoreError::Replay(path.to_path_buf(), n + 1, e.to_string()))?;
            store.index(event);
        }
        Ok(store)
    }

    fn index(&mut self, event: RedeemEvent) {
        let totals = self.totals.entry(event.server_id.clone()).or_default();
        totals.redemptions += 1;
        totals.gas = totals.gas.saturating_add(event.gas_added);
        totals.sat = totals.sat.saturating_add(event.sat_value);
        if let Some(epoch) = event.epoch {
            for tag in &event.tags_hex {
                self.seen_tags.insert((epoch, tag.clone()));
            }
        }
        self.answers
            .insert((event.server_id.clone(), event.nonce_hex.clone()), event);
    }

    /// Whether an ARC tag was already consumed under `epoch`.
    pub fn has_tag(&self, epoch: u32, tag_hex: &str) -> bool {
        self.seen_tags.contains(&(epoch, tag_hex.to_owned()))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The answer already given for this `(server_id, nonce)`, if any.
    pub fn answer(&self, server_id: &str, nonce_hex: &str) -> Option<RedeemResponseV1> {
        self.answers
            .get(&(server_id.to_owned(), nonce_hex.to_owned()))
            .map(RedeemEvent::response)
    }

    /// Append one redemption durably.
    pub fn record(&mut self, event: RedeemEvent) -> Result<(), RedeemStoreError> {
        let mut line = serde_json::to_string(&event)
            .map_err(|e| RedeemStoreError::Append(std::io::Error::other(e)))?;
        line.push('\n');
        self.file
            .write_all(line.as_bytes())
            .map_err(RedeemStoreError::Append)?;
        self.file.sync_data().map_err(RedeemStoreError::Append)?;
        self.index(event);
        Ok(())
    }

    pub fn totals(&self) -> &BTreeMap<String, ServerTotals> {
        &self.totals
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use pir_credit::issuer::RedeemItemV1;
    use pir_identity::sign_identity_cert;

    const NOW: u64 = 1_800_000_000;

    fn operator() -> SigningKey {
        SigningKey::from_bytes(&[1u8; 32])
    }

    fn server_key() -> SigningKey {
        SigningKey::from_bytes(&[2u8; 32])
    }

    fn cert(server_id: &str) -> IdentityCert {
        sign_identity_cert(
            &operator(),
            server_id,
            server_key().verifying_key().to_bytes(),
            0,
            0,
        )
    }

    fn request(
        server_id: &str,
        cert: &IdentityCert,
        unix_time: u64,
        items: &[(u8, Vec<u8>)],
    ) -> RedeemRequestV1 {
        let nonce = [0x11u8; REDEEM_NONCE_LEN];
        let borrowed: Vec<(u8, &[u8])> = items.iter().map(|(k, p)| (*k, p.as_slice())).collect();
        let preimage = RedeemRequestV1::signing_preimage(server_id, &nonce, unix_time, &borrowed);
        RedeemRequestV1 {
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
        }
    }

    #[test]
    fn a_well_formed_request_from_a_certified_server_verifies() {
        let cert = cert("pir1");
        let request = request("pir1", &cert, NOW, &[(1, b"cashuB".to_vec())]);
        let verified =
            verify_request(&request, &[operator().verifying_key()], NOW + 10, 300).unwrap();
        assert_eq!(verified.server_id, "pir1");
        assert_eq!(verified.nonce, [0x11u8; REDEEM_NONCE_LEN]);
        assert_eq!(verified.items, vec![(1, b"cashuB".to_vec())]);
    }

    #[test]
    fn every_link_of_the_chain_is_checked() {
        let cert = cert("pir1");
        let good = request("pir1", &cert, NOW, &[(1, vec![1])]);
        let ops = [operator().verifying_key()];
        let status = |r: Result<VerifiedRedeem, ApiError>| r.unwrap_err().status.as_u16();
        // No operator keys configured.
        assert_eq!(status(verify_request(&good, &[], NOW, 300)), 401);
        // Unknown operator.
        let other = [SigningKey::from_bytes(&[9u8; 32]).verifying_key()];
        assert_eq!(status(verify_request(&good, &other, NOW, 300)), 401);
        // server_id must match the certificate.
        let mut renamed = good.clone();
        renamed.server_id = "pir2".into();
        assert_eq!(status(verify_request(&renamed, &ops, NOW, 300)), 401);
        // Clock skew.
        assert_eq!(status(verify_request(&good, &ops, NOW + 301, 300)), 400);
        assert_eq!(status(verify_request(&good, &ops, NOW - 301, 300)), 400);
        // Tampered item changes the preimage.
        let mut tampered = good.clone();
        tampered.items[0].payload_hex = "02".into();
        assert_eq!(status(verify_request(&tampered, &ops, NOW, 300)), 401);
        // Signed by a key the certificate does not vouch for.
        let mut foreign = good.clone();
        let preimage = RedeemRequestV1::signing_preimage("pir1", &[0x11u8; 16], NOW, &[(1, &[1])]);
        foreign.signature_hex = hex::encode(
            SigningKey::from_bytes(&[3u8; 32])
                .sign(&preimage)
                .to_bytes(),
        );
        assert_eq!(status(verify_request(&foreign, &ops, NOW, 300)), 401);
        // Malformed encodings.
        let mut bad_nonce = good.clone();
        bad_nonce.nonce_hex = "abcd".into();
        assert_eq!(status(verify_request(&bad_nonce, &ops, NOW, 300)), 400);
        let mut bad_cert = good.clone();
        bad_cert.identity_cert_hex = "zz".into();
        assert_eq!(status(verify_request(&bad_cert, &ops, NOW, 300)), 400);
        let mut no_items = good.clone();
        no_items.items.clear();
        assert_eq!(status(verify_request(&no_items, &ops, NOW, 300)), 400);
        // An expired certificate.
        let expired = sign_identity_cert(
            &operator(),
            "pir1",
            server_key().verifying_key().to_bytes(),
            0,
            NOW as i64 - 1,
        );
        let request = request("pir1", &expired, NOW, &[(1, vec![1])]);
        assert_eq!(status(verify_request(&request, &ops, NOW, 300)), 401);
    }

    #[test]
    fn redeem_store_replays_answers_and_sums_per_server() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("redeem.jsonl");
        let event = |server: &str, nonce: &str, gas: u64, sat: u64| RedeemEvent {
            server_id: server.into(),
            nonce_hex: nonce.into(),
            unix_time: NOW,
            gas_added: gas,
            sat_value: sat,
            items_accepted: 1,
            issuer_signature_hex: "00".repeat(64),
            epoch: None,
            tags_hex: Vec::new(),
        };
        {
            let mut store = RedeemStore::open(&path).unwrap();
            store.record(event("pir1", "aa", 72_000, 10)).unwrap();
            store.record(event("pir1", "bb", 144_000, 20)).unwrap();
            store.record(event("pir2", "aa", 7_200, 1)).unwrap();
            let mut arc = event("pir2", "cc", 144_000, 20);
            arc.epoch = Some(231);
            arc.tags_hex = vec!["t1".into(), "t2".into()];
            store.record(arc).unwrap();
        }
        let store = RedeemStore::open(&path).unwrap();
        assert!(store.has_tag(231, "t1") && store.has_tag(231, "t2"));
        assert!(!store.has_tag(232, "t1") && !store.has_tag(231, "t3"));
        assert_eq!(store.answer("pir1", "aa").unwrap().gas_added, 72_000);
        assert_eq!(store.answer("pir2", "aa").unwrap().gas_added, 7_200);
        assert!(store.answer("pir2", "bb").is_none());
        assert_eq!(
            store.totals()["pir1"],
            ServerTotals {
                redemptions: 2,
                gas: 216_000,
                sat: 30
            }
        );
        assert_eq!(store.totals()["pir2"].sat, 21);
        std::fs::write(&path, "not json\n").unwrap();
        assert!(matches!(
            RedeemStore::open(&path),
            Err(RedeemStoreError::Replay(_, 1, _))
        ));
    }
}
