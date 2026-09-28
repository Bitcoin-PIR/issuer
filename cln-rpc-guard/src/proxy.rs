//! The socket proxy: one upstream CLN connection per downstream connection,
//! requests checked and forwarded unchanged, responses copied back verbatim.

use crate::{check, next_json_object, InvoiceLimiter, Policy, Rejection};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{mpsc, Mutex, Semaphore};

#[derive(Clone, Debug)]
pub struct GuardConfig {
    /// The node's own `lightning-rpc` socket.
    pub upstream: PathBuf,
    pub policy: Policy,
    /// Forwarded `invoice` calls per minute across all connections.
    pub invoices_per_minute: usize,
    pub max_connections: usize,
    /// A downstream request larger than this closes the connection.
    pub max_request_bytes: usize,
}

pub struct Guard {
    config: GuardConfig,
    limiter: Mutex<InvoiceLimiter>,
    connections: Arc<Semaphore>,
}

impl Guard {
    pub fn new(config: GuardConfig) -> Arc<Self> {
        Arc::new(Self {
            limiter: Mutex::new(InvoiceLimiter::new(config.invoices_per_minute)),
            connections: Arc::new(Semaphore::new(config.max_connections)),
            config,
        })
    }

    /// Accepts downstream connections until the listener fails.
    pub async fn serve(self: Arc<Self>, listener: UnixListener) -> std::io::Result<()> {
        loop {
            let (stream, _) = listener.accept().await?;
            let permit = match Arc::clone(&self.connections).try_acquire_owned() {
                Ok(p) => p,
                Err(_) => {
                    tracing::warn!("connection limit reached; refusing a downstream connection");
                    drop(stream);
                    continue;
                }
            };
            let guard = Arc::clone(&self);
            tokio::spawn(async move {
                if let Err(e) = guard.handle(stream).await {
                    tracing::info!(error = %e, "connection ended");
                }
                drop(permit);
            });
        }
    }

    async fn handle(&self, downstream: UnixStream) -> std::io::Result<()> {
        let upstream = UnixStream::connect(&self.config.upstream).await?;
        let (mut down_r, mut down_w) = downstream.into_split();
        let (mut up_r, mut up_w) = upstream.into_split();

        // Everything written downstream goes through one channel: node
        // responses and the guard's own rejections never interleave.
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(64);
        let writer = tokio::spawn(async move {
            while let Some(bytes) = rx.recv().await {
                if down_w.write_all(&bytes).await.is_err() {
                    break;
                }
            }
            let _ = down_w.shutdown().await;
        });
        let tx_up = tx.clone();
        let upstream_reader = tokio::spawn(async move {
            let mut buf = vec![0u8; 16 * 1024];
            loop {
                match up_r.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if tx_up.send(buf[..n].to_vec()).await.is_err() {
                            break;
                        }
                    }
                }
            }
        });

        let mut pending: Vec<u8> = Vec::new();
        let mut upstream_gone = false;
        let mut malformed = false;
        let mut chunk = vec![0u8; 16 * 1024];
        let result: std::io::Result<()> = loop {
            let n = match down_r.read(&mut chunk).await {
                Ok(0) => break Ok(()),
                Ok(n) => n,
                Err(e) => break Err(e),
            };
            pending.extend_from_slice(&chunk[..n]);
            loop {
                match next_json_object(&pending) {
                    Ok(None) => break,
                    Ok(Some((start, end, request))) => {
                        match self.decide(&request).await {
                            Ok(method) => {
                                tracing::info!(method, "forwarded");
                                if up_w.write_all(&pending[start..end]).await.is_err() {
                                    tracing::warn!("upstream write failed; closing");
                                    upstream_gone = true;
                                    break;
                                }
                            }
                            Err(rejection) => {
                                tracing::warn!(
                                    method = request.get("method").and_then(|m| m.as_str()).unwrap_or("?"),
                                    reason = %rejection.message,
                                    "rejected"
                                );
                                let bytes = rejection.response_bytes(request.get("id"));
                                if tx.send(bytes).await.is_err() {
                                    break;
                                }
                            }
                        }
                        pending.drain(..end);
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "malformed JSON from downstream; closing");
                        malformed = true;
                        break;
                    }
                }
            }
            if malformed {
                break Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "malformed JSON from downstream",
                ));
            }
            if upstream_gone {
                break Ok(());
            }
            if pending.len() > self.config.max_request_bytes {
                tracing::warn!("downstream request exceeds the size limit; closing");
                break Ok(());
            }
        };
        let _ = up_w.shutdown().await;
        drop(tx);
        let _ = upstream_reader.await;
        let _ = writer.await;
        result
    }

    async fn decide(&self, request: &serde_json::Value) -> Result<&'static str, Rejection> {
        let method = check(request, &self.config.policy)?;
        if method == "invoice" && !self.limiter.lock().await.admit(Instant::now()) {
            return Err(Rejection {
                code: -32000,
                message: "invoice rate limit reached; retry later".to_owned(),
            });
        }
        Ok(method)
    }
}
