//! Idempotency and audit store: an append-only JSON-lines file with an
//! in-memory index keyed by the token key.
//!
//! Each line is one [`Event`]; the last event for a key is its state. The file
//! is the operator's reconciliation log (every token seen, what it bought,
//! every swap failure) and survives restarts: the issuer replays it at
//! startup. Writes are appended with `fsync` before the request proceeds.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// A v1 session grant, as issued before the grants were retired (2026-09).
/// Kept so old log lines replay and their tokens stay spent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuedGrant {
    pub grant_base64: String,
    pub grant_id_hex: String,
    pub credits: u32,
    pub issued_at: u64,
    pub expires_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum State {
    /// The swap is about to be attempted. A `pending` state at startup means
    /// the process died mid-swap; the outcome at the mint is unknown.
    Pending { first_seen: u64 },
    /// The swap failed and the mint did not consume the token (or reported
    /// it as already spent). The client may retry with the same token.
    Failed { at: u64, reason: String },
    /// Retired v1 path: the mint accepted the token and a session grant was
    /// signed. Only replayed from old logs; the token counts as spent.
    Issued {
        grant: IssuedGrant,
        /// Value the mint actually credited (may be below the face value
        /// when the mint charges input fees; the operator absorbs that).
        received: u64,
        mint: String,
        unit: String,
    },
    /// The mint accepted the token presented through a PIR server's
    /// `POST /v2/redeem`; its value was booked to that server.
    Redeemed {
        server_id: String,
        received: u64,
        mint: String,
        unit: String,
    },
    /// The mint accepted the token presented to `POST /v2/credentials` and
    /// an ARC credential was issued under `epoch` for `request_hex`.
    Credentialed {
        epoch: u32,
        request_hex: String,
        response_hex: String,
        received: u64,
        mint: String,
        unit: String,
    },
    /// x402 `exact/lnbtc`: the Lightning payment with this hash was proven
    /// (preimage) and an ARC credential issued under `epoch` for
    /// `request_hex`. Keyed `x402:<network>:<payment_hash>`, which is also
    /// the facilitator's replay entry: a second claim of the same payment is
    /// `duplicate_settlement`.
    X402Credentialed {
        network: String,
        payment_hash_hex: String,
        msat: u64,
        epoch: u32,
        request_hex: String,
        response_hex: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    pub token_key_hex: String,
    #[serde(flatten)]
    pub state: State,
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("open {0}: {1}")]
    Open(PathBuf, std::io::Error),
    #[error("replay {0} line {1}: {2}")]
    Replay(PathBuf, usize, String),
    #[error("append: {0}")]
    Append(std::io::Error),
}

pub struct Store {
    path: PathBuf,
    file: File,
    index: HashMap<String, State>,
}

impl Store {
    /// Open (creating if needed) and replay the log.
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .open(path)
            .map_err(|e| StoreError::Open(path.to_path_buf(), e))?;
        let mut index = HashMap::new();
        let reader =
            BufReader::new(File::open(path).map_err(|e| StoreError::Open(path.to_path_buf(), e))?);
        for (n, line) in reader.lines().enumerate() {
            let line =
                line.map_err(|e| StoreError::Replay(path.to_path_buf(), n + 1, e.to_string()))?;
            if line.trim().is_empty() {
                continue;
            }
            let event: Event = serde_json::from_str(&line)
                .map_err(|e| StoreError::Replay(path.to_path_buf(), n + 1, e.to_string()))?;
            index.insert(event.token_key_hex, event.state);
        }
        Ok(Self {
            path: path.to_path_buf(),
            file,
            index,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn get(&self, token_key_hex: &str) -> Option<&State> {
        self.index.get(token_key_hex)
    }

    /// Append one event durably and update the index.
    pub fn record(&mut self, token_key_hex: &str, state: State) -> Result<(), StoreError> {
        let event = Event {
            token_key_hex: token_key_hex.to_string(),
            state: state.clone(),
        };
        let mut line = serde_json::to_string(&event)
            .map_err(|e| StoreError::Append(std::io::Error::other(e)))?;
        line.push('\n');
        self.file
            .write_all(line.as_bytes())
            .map_err(StoreError::Append)?;
        self.file.sync_data().map_err(StoreError::Append)?;
        self.index.insert(token_key_hex.to_string(), state);
        Ok(())
    }

    /// Number of tokens redeemed through a server.
    pub fn redeemed_count(&self) -> usize {
        self.index
            .values()
            .filter(|s| matches!(s, State::Redeemed { .. }))
            .count()
    }

    /// Tokens whose swap outcome is unknown (process died mid-swap).
    pub fn pending_keys(&self) -> Vec<String> {
        self.index
            .iter()
            .filter(|(_, s)| matches!(s, State::Pending { .. }))
            .map(|(k, _)| k.clone())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn issued(credits: u32) -> State {
        State::Issued {
            grant: IssuedGrant {
                grant_base64: "AAAA".into(),
                grant_id_hex: "00".repeat(16),
                credits,
                issued_at: 1,
                expires_at: 2,
            },
            received: 210,
            mint: "https://mint.example".into(),
            unit: "sat".into(),
        }
    }

    #[test]
    fn replay_keeps_the_last_state_per_key_including_retired_grants() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("grants.jsonl");
        {
            let mut store = Store::open(&path).unwrap();
            store
                .record("k1", State::Pending { first_seen: 1 })
                .unwrap();
            store.record("k1", issued(1000)).unwrap();
            store
                .record("k2", State::Pending { first_seen: 5 })
                .unwrap();
            store
                .record(
                    "k3",
                    State::Failed {
                        at: 6,
                        reason: "net".into(),
                    },
                )
                .unwrap();
        }
        let store = Store::open(&path).unwrap();
        assert_eq!(store.get("k1"), Some(&issued(1000)));
        assert_eq!(store.get("k2"), Some(&State::Pending { first_seen: 5 }));
        assert!(matches!(store.get("k3"), Some(State::Failed { .. })));
        assert_eq!(store.pending_keys(), vec!["k2".to_string()]);
        assert_eq!(std::fs::read_to_string(&path).unwrap().lines().count(), 4);
    }

    #[test]
    fn corrupt_line_is_refused_at_startup() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("grants.jsonl");
        std::fs::write(
            &path,
            "{\"token_key_hex\":\"k\",\"state\":\"pending\",\"first_seen\":1}\nnot json\n",
        )
        .unwrap();
        assert!(matches!(
            Store::open(&path),
            Err(StoreError::Replay(_, 2, _))
        ));
    }
}
