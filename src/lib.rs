//! BitcoinPIR issuer: the credit issuer. Cashu ecash is the only credit. It
//! keeps a Cashu wallet at the mint, swaps into it the ecash a PIR server
//! forwards (`POST /v2/redeem`, answers signed with the [`issuer_key`]),
//! books the value to that server's settlement ledger in gas, and sells
//! ecash from the wallet for Lightning (`POST /v2/x402/ecash`, [`ecash`]).
//!
//! The HTTP contract is `docs/CREDITS.md` "Issuer API" in the
//! Bitcoin-PIR/Bitcoin-PIR repository; its types are the `pir-credit` crate
//! from the same repository, pinned here by git revision so the issuer and
//! the PIR servers can never disagree on the bytes. The v1 session grants
//! (`/v1/`) and the ARC credentials are retired.

pub mod api;
pub mod cashu;
pub mod config;
pub mod ecash;
pub mod issuer_key;
pub mod redeem;
pub mod store;
pub mod x402;

/// Unix seconds now; the only place the issuer reads the clock.
pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
