//! `bpir-cln-rpc-guard` — allowlisting proxy for the Core Lightning RPC socket.
//!
//! ```text
//! bpir-cln-rpc-guard --upstream /srv/lightning/bitcoin/lightning-rpc \
//!                    --listen /run/bpir-cln-rpc-guard/rpc.sock
//! ```
//!
//! Runs in the node socket's group and exposes `--listen` (mode 0660, group =
//! the unit's `Group=`) to the issuer. Only `invoice`, `listinvoices`, and
//! `waitinvoice` pass, with the parameter bounds below.

use anyhow::Context;
use bpir_cln_rpc_guard::proxy::{Guard, GuardConfig};
use bpir_cln_rpc_guard::Policy;
use clap::Parser;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use tokio::net::UnixListener;

#[derive(Parser)]
#[command(
    name = "bpir-cln-rpc-guard",
    about = "Allowlisting proxy for the CLN JSON-RPC socket"
)]
struct Args {
    /// Core Lightning's `lightning-rpc` socket.
    #[arg(long)]
    upstream: PathBuf,
    /// Socket to create for the issuer.
    #[arg(long)]
    listen: PathBuf,
    /// Required prefix of every invoice label the issuer may create or read.
    #[arg(long, default_value = "bpir-x402-")]
    label_prefix: String,
    #[arg(long, default_value_t = 1_000)]
    min_msat: u64,
    #[arg(long, default_value_t = 100_000_000)]
    max_msat: u64,
    #[arg(long, default_value_t = 3_600)]
    max_expiry_secs: u64,
    #[arg(long, default_value_t = 4_096)]
    max_description_bytes: usize,
    #[arg(long, default_value_t = 120)]
    invoices_per_minute: usize,
    #[arg(long, default_value_t = 16)]
    max_connections: usize,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env().add_directive("info".parse()?),
        )
        .init();
    let args = Args::parse();
    let config = GuardConfig {
        upstream: args.upstream.clone(),
        policy: Policy {
            label_prefix: args.label_prefix,
            min_msat: args.min_msat,
            max_msat: args.max_msat,
            max_expiry_secs: args.max_expiry_secs,
            max_description_bytes: args.max_description_bytes,
            max_label_bytes: 128,
        },
        invoices_per_minute: args.invoices_per_minute,
        max_connections: args.max_connections,
        max_request_bytes: 64 * 1024,
    };
    anyhow::ensure!(
        args.upstream.exists(),
        "upstream socket {} does not exist",
        args.upstream.display()
    );
    if args.listen.exists() {
        std::fs::remove_file(&args.listen)
            .with_context(|| format!("removing stale socket {}", args.listen.display()))?;
    }
    let listener = UnixListener::bind(&args.listen)
        .with_context(|| format!("binding {}", args.listen.display()))?;
    std::fs::set_permissions(&args.listen, std::fs::Permissions::from_mode(0o660))
        .with_context(|| format!("chmod 0660 {}", args.listen.display()))?;
    tracing::info!(
        upstream = %args.upstream.display(),
        listen = %args.listen.display(),
        label_prefix = %config.policy.label_prefix,
        min_msat = config.policy.min_msat,
        max_msat = config.policy.max_msat,
        max_expiry_secs = config.policy.max_expiry_secs,
        invoices_per_minute = config.invoices_per_minute,
        "cln-rpc-guard: forwarding invoice, listinvoices, waitinvoice only"
    );
    let guard = Guard::new(config);
    let listen_path = args.listen.clone();
    let served = tokio::select! {
        r = guard.serve(listener) => r.map_err(anyhow::Error::from),
        _ = shutdown_signal() => Ok(()),
    };
    let _ = std::fs::remove_file(&listen_path);
    served
}

async fn shutdown_signal() {
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("SIGTERM handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {},
        _ = term.recv() => {},
    }
}
