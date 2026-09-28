//! `bpir-issuer` — operator CLI.
//!
//! ```text
//! bpir-issuer serve --config /etc/bitcoinpir/issuer/config.toml
//! bpir-issuer keygen --out grant.key            # issuer signing seed (prints the pubkey to pin)
//! bpir-issuer wallet-seed --out wallet.seed     # Cashu wallet seed
//! bpir-issuer pubkey --key grant.key            # print the public key for --credit-issuer-pubkey
//! bpir-issuer balance --config config.toml      # ecash held per (mint, unit)
//! bpir-issuer mnemonic --out mint.seed          # BIP39 phrase for cdk-mintd --seed-file
//! bpir-issuer settlement --config config.toml   # gas and sat redeemed per PIR server
//! bpir-issuer arc-seed --out arc.seed           # ARC master seed (per-epoch issuer keys)
//! ```

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use clap::{Parser, Subcommand};
use tokio::sync::Mutex;

use bpir_issuer::api::{build_router, AppState};
use bpir_issuer::arc::ArcIssuer;
use bpir_issuer::cashu::CdkSwapper;
use bpir_issuer::config::{read_seed_file, Config};
use bpir_issuer::issuer_key::IssuerKey;
use bpir_issuer::redeem::RedeemStore;
use bpir_issuer::store::Store;
use bpir_issuer::x402::receiver::GuardReceiver;
use bpir_issuer::x402::server::X402State;

#[derive(Parser)]
#[command(
    name = "bpir-issuer",
    about = "BitcoinPIR issuer: credits for Cashu ecash",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the HTTP service.
    Serve {
        #[arg(long)]
        config: PathBuf,
    },
    /// Generate the 32-byte Ed25519 issuer signing seed (mode 0600) and print
    /// its public key, which every PIR server pins with --credit-issuer-pubkey.
    Keygen {
        #[arg(long)]
        out: PathBuf,
    },
    /// Generate the 64-byte Cashu wallet seed (mode 0600).
    WalletSeed {
        #[arg(long)]
        out: PathBuf,
    },
    /// Print the public key of an issuer signing seed.
    Pubkey {
        #[arg(long)]
        key: PathBuf,
    },
    /// Print the ecash balance the issuer holds per (mint, unit).
    Balance {
        #[arg(long)]
        config: PathBuf,
    },
    /// Print gas and sat redeemed per PIR server (`POST /v2/redeem` ledger).
    Settlement {
        #[arg(long)]
        config: PathBuf,
    },
    /// Generate the 32-byte ARC master seed (mode 0600); every epoch's
    /// issuer keys derive from it. Back it up: it is the credentials.
    ArcSeed {
        #[arg(long)]
        out: PathBuf,
    },
    /// Generate a BIP39 mnemonic (24 words, 256-bit entropy) into a mode-0400
    /// file, for a mint's `--seed-file`. The phrase is never printed.
    Mnemonic {
        #[arg(long)]
        out: PathBuf,
        #[arg(long, default_value_t = 24)]
        words: usize,
    },
}

fn write_secret(path: &PathBuf, bytes: &[u8]) -> anyhow::Result<()> {
    write_secret_mode(path, bytes, 0o600)
}

fn write_secret_mode(path: &PathBuf, bytes: &[u8], mode: u32) -> anyhow::Result<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;
    let mut file = options
        .open(path)
        .with_context(|| format!("create {}", path.display()))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn load_seed32(path: &std::path::Path) -> anyhow::Result<[u8; 32]> {
    let seed = read_seed_file(path, 32).map_err(anyhow::Error::msg)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&seed);
    Ok(out)
}

fn load_wallet_seed(path: &std::path::Path) -> anyhow::Result<[u8; 64]> {
    let seed = read_seed_file(path, 64).map_err(anyhow::Error::msg)?;
    let mut out = [0u8; 64];
    out.copy_from_slice(&seed);
    Ok(out)
}

/// Wallet units: the `/v2` paths (Cashu items on `/v2/redeem`,
/// `/v2/credentials`) take sat tokens only.
fn wallet_units() -> Vec<String> {
    vec!["sat".to_string()]
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env().add_directive("info".parse()?),
        )
        .init();
    match Cli::parse().command {
        Command::Keygen { out } => {
            let mut seed = zeroize::Zeroizing::new([0u8; 32]);
            getrandom::getrandom(seed.as_mut()).map_err(|e| anyhow::anyhow!("getrandom: {e}"))?;
            write_secret(&out, seed.as_ref())?;
            let issuer = IssuerKey::new(&seed);
            eprintln!(
                "wrote issuer signing seed (32 bytes, mode 0600) to {}",
                out.display()
            );
            eprintln!("public key (pin on every PIR server with --credit-issuer-pubkey):");
            println!("{}", issuer.public_key_hex());
        }
        Command::WalletSeed { out } => {
            let mut seed = zeroize::Zeroizing::new([0u8; 64]);
            getrandom::getrandom(seed.as_mut()).map_err(|e| anyhow::anyhow!("getrandom: {e}"))?;
            write_secret(&out, seed.as_ref())?;
            eprintln!(
                "wrote wallet seed (64 bytes, mode 0600) to {}",
                out.display()
            );
        }
        Command::Pubkey { key } => {
            let seed = zeroize::Zeroizing::new(load_seed32(&key)?);
            println!("{}", IssuerKey::new(&seed).public_key_hex());
        }
        Command::Mnemonic { out, words } => {
            anyhow::ensure!(
                matches!(words, 12 | 15 | 18 | 21 | 24),
                "--words must be 12, 15, 18, 21, or 24"
            );
            let phrase = zeroize::Zeroizing::new(
                bip39::Mnemonic::generate_in(bip39::Language::English, words)
                    .map_err(|e| anyhow::anyhow!("bip39: {e}"))?
                    .to_string(),
            );
            write_secret_mode(&out, format!("{}\n", phrase.as_str()).as_bytes(), 0o400)?;
            eprintln!(
                "wrote {words}-word BIP39 mnemonic (mode 0400) to {}",
                out.display()
            );
        }
        Command::Balance { config } => {
            let config = Config::load(&config)?;
            let seed = zeroize::Zeroizing::new(load_wallet_seed(&config.wallet_seed_path)?);
            let swapper = CdkSwapper::open(
                &config.wallet_db_path,
                *seed,
                &config.mints,
                &wallet_units(),
                std::time::Duration::from_secs(30),
            )
            .await?;
            for ((mint, unit), balance) in swapper.balances().await {
                match balance {
                    Ok(b) => println!("{mint} {unit} {b}"),
                    Err(e) => println!("{mint} {unit} error: {e}"),
                }
            }
        }
        Command::ArcSeed { out } => {
            let mut seed = zeroize::Zeroizing::new([0u8; 32]);
            getrandom::getrandom(seed.as_mut()).map_err(|e| anyhow::anyhow!("getrandom: {e}"))?;
            write_secret(&out, seed.as_ref())?;
            eprintln!(
                "wrote ARC master seed (32 bytes, mode 0600) to {}",
                out.display()
            );
        }
        Command::Settlement { config } => {
            let config = Config::load(&config)?;
            let store = RedeemStore::open(&config.redeem_store_path())?;
            println!("server_id redemptions gas sat");
            for (server_id, totals) in store.totals() {
                println!(
                    "{server_id} {} {} {}",
                    totals.redemptions, totals.gas, totals.sat
                );
            }
        }
        Command::Serve { config } => {
            let config = Config::load(&config)?;
            let issuer_seed = zeroize::Zeroizing::new(load_seed32(&config.grant_key_path)?);
            let issuer = IssuerKey::new(&issuer_seed);
            let wallet_seed = zeroize::Zeroizing::new(load_wallet_seed(&config.wallet_seed_path)?);
            let swapper = CdkSwapper::open(
                &config.wallet_db_path,
                *wallet_seed,
                &config.mints,
                &wallet_units(),
                std::time::Duration::from_secs(45),
            )
            .await?;
            let store = Store::open(&config.store_path)?;
            let redeem_store = RedeemStore::open(&config.redeem_store_path())?;
            let operator_keys = config.operator_keys();
            let arc = match &config.arc {
                Some(arc_config) => {
                    let seed = zeroize::Zeroizing::new(load_seed32(&arc_config.seed_path)?);
                    Some(ArcIssuer::new(
                        *seed,
                        arc_config.epoch_secs,
                        arc_config.grace_secs,
                        arc_config.presentation_limit,
                    ))
                }
                None => None,
            };
            if operator_keys.is_empty() {
                tracing::warn!("operator_pubkeys is empty: POST /v2/redeem refuses every server");
            }
            let pending = store.pending_keys();
            if !pending.is_empty() {
                tracing::warn!(count = pending.len(), "tokens with unknown swap outcome in the store; reconcile against the wallet balance");
            }
            tracing::info!(
                listen = %config.listen,
                issuer_pubkey_hex = %issuer.public_key_hex(),
                mints = ?config.mints,
                redeemed_tokens = store.redeemed_count(),
                store = %store.path().display(),
                redeem_store = %redeem_store.path().display(),
                operator_keys = operator_keys.len(),
                arc = arc.is_some(),
                "bpir-issuer starting"
            );
            let x402 = match &config.x402 {
                Some(x402_config) => {
                    let receiver = GuardReceiver::new(
                        x402_config.guard_socket.clone(),
                        x402_config.label_prefix.clone(),
                    );
                    let state = X402State::new(x402_config.clone(), Box::new(receiver))
                        .map_err(|e| anyhow::anyhow!("[x402]: {e}"))?;
                    tracing::info!(
                        network = state.network.caip2(),
                        pay_to = %x402_config.node_pubkey_hex,
                        resource = %state.resource_url(),
                        guard = %x402_config.guard_socket.display(),
                        max_timeout_secs = x402_config.max_timeout_secs,
                        "x402 exact/lnbtc enabled on POST /v2/credentials"
                    );
                    Some(state)
                }
                None => None,
            };
            let listen = config.listen;
            let state = Arc::new(AppState {
                config,
                issuer,
                swapper: Box::new(swapper),
                store: Mutex::new(store),
                redeem_store: Mutex::new(redeem_store),
                operator_keys,
                arc,
                x402,
                clock: Box::new(bpir_issuer::unix_now),
            });
            let listener = tokio::net::TcpListener::bind(listen)
                .await
                .with_context(|| format!("bind {listen}"))?;
            axum::serve(listener, build_router(state))
                .with_graceful_shutdown(async {
                    let _ = tokio::signal::ctrl_c().await;
                    tracing::info!("shutting down");
                })
                .await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_wallet_takes_sat() {
        // Regression: a wallet opened only for `/v1` offer units left the
        // `/v2` paths without one ("no wallet for <mint> (sat)").
        assert_eq!(wallet_units(), vec!["sat".to_string()]);
    }
}
