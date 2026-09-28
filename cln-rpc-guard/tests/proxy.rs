//! End to end through real Unix sockets: a fake node that echoes the method of
//! every request it receives, the guard in front of it, and a client.

use bpir_cln_rpc_guard::proxy::{Guard, GuardConfig};
use bpir_cln_rpc_guard::{next_json_object, Policy};
use serde_json::{json, Value};
use std::path::Path;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

fn fake_node(path: &Path, seen: Arc<Mutex<Vec<String>>>) {
    let listener = UnixListener::bind(path).unwrap();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = listener.accept().await.unwrap();
            let seen = Arc::clone(&seen);
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    let n = match s.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => n,
                    };
                    buf.extend_from_slice(&chunk[..n]);
                    while let Some((_, end, req)) = next_json_object(&buf).unwrap() {
                        let method = req["method"].as_str().unwrap().to_owned();
                        seen.lock().unwrap().push(method.clone());
                        let resp =
                            json!({"jsonrpc":"2.0","id":req["id"],"result":{"method":method}});
                        let mut bytes = serde_json::to_vec(&resp).unwrap();
                        bytes.extend_from_slice(b"\n\n");
                        s.write_all(&bytes).await.unwrap();
                        buf.drain(..end);
                    }
                }
            });
        }
    });
}

/// Client side with a persistent buffer: two responses can arrive in one read.
struct Client {
    stream: UnixStream,
    buf: Vec<u8>,
}

impl Client {
    async fn connect(path: &Path) -> Self {
        Self {
            stream: UnixStream::connect(path).await.unwrap(),
            buf: Vec::new(),
        }
    }

    async fn send(&mut self, bytes: &[u8]) {
        self.stream.write_all(bytes).await.unwrap();
    }

    async fn next_response(&mut self) -> Value {
        let mut chunk = [0u8; 4096];
        loop {
            if let Some(pos) = self.buf.windows(2).position(|w| w == b"\n\n") {
                let v: Value = serde_json::from_slice(&self.buf[..pos]).unwrap();
                self.buf.drain(..pos + 2);
                return v;
            }
            let n = self.stream.read(&mut chunk).await.unwrap();
            assert!(n > 0, "connection closed before a response");
            self.buf.extend_from_slice(&chunk[..n]);
        }
    }
}

fn invoice_request(id: u64) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "jsonrpc": "2.0", "id": id, "method": "invoice",
        "params": {"amount_msat": 1_000_000, "label": format!("bpir-x402-{id}"),
                   "description": "{\"domain\":\"x402:exact:lnbtc:bolt11:http:1\"}",
                   "expiry": 900, "deschashonly": true}
    }))
    .unwrap()
}

fn start_guard(
    dir: &Path,
    invoices_per_minute: usize,
) -> (std::path::PathBuf, Arc<Mutex<Vec<String>>>) {
    let upstream = dir.join("lightning-rpc");
    let listen = dir.join("guard.sock");
    let seen = Arc::new(Mutex::new(Vec::new()));
    fake_node(&upstream, Arc::clone(&seen));
    let guard = Guard::new(GuardConfig {
        upstream,
        policy: Policy::default(),
        invoices_per_minute,
        max_connections: 4,
        max_request_bytes: 64 * 1024,
    });
    tokio::spawn(guard.serve(UnixListener::bind(&listen).unwrap()));
    (listen, seen)
}

#[tokio::test]
async fn forwards_allowed_requests_and_answers_rejections_itself() {
    let dir = tempfile::tempdir().unwrap();
    let (listen, seen) = start_guard(dir.path(), 2);
    let mut client = Client::connect(&listen).await;

    // Two concatenated allowed requests in one write: two node responses.
    let mut two = invoice_request(1);
    two.extend_from_slice(&invoice_request(2));
    client.send(&two).await;
    let r1 = client.next_response().await;
    let r2 = client.next_response().await;
    assert_eq!(r1["result"]["method"], "invoice");
    assert_eq!(r2["result"]["method"], "invoice");
    assert_eq!(r1["id"], 1);
    assert_eq!(r2["id"], 2);

    // Third invoice within the minute hits the rate limit; never reaches the node.
    client.send(&invoice_request(3)).await;
    let limited = client.next_response().await;
    assert_eq!(limited["error"]["code"], -32000);
    assert_eq!(limited["id"], 3);

    // A disallowed method is answered by the guard with -32601.
    let pay = serde_json::to_vec(
        &json!({"jsonrpc":"2.0","id":"p","method":"pay","params":{"bolt11":"lnbc1"}}),
    )
    .unwrap();
    client.send(&pay).await;
    let rejected = client.next_response().await;
    assert_eq!(rejected["error"]["code"], -32601);
    assert_eq!(rejected["id"], "p");
    assert!(rejected["error"]["message"]
        .as_str()
        .unwrap()
        .contains("not allowed"));

    // Scoped read-only calls pass.
    let wait = serde_json::to_vec(
        &json!({"jsonrpc":"2.0","id":9,"method":"waitinvoice","params":{"label":"bpir-x402-1"}}),
    )
    .unwrap();
    client.send(&wait).await;
    assert_eq!(
        client.next_response().await["result"]["method"],
        "waitinvoice"
    );

    assert_eq!(
        *seen.lock().unwrap(),
        vec!["invoice", "invoice", "waitinvoice"]
    );
}

#[tokio::test]
async fn malformed_json_closes_the_connection() {
    let dir = tempfile::tempdir().unwrap();
    let (listen, _seen) = start_guard(dir.path(), 10);
    let mut client = Client::connect(&listen).await;
    client.send(b"{]").await;
    let mut buf = [0u8; 16];
    let n = client.stream.read(&mut buf).await.unwrap();
    assert_eq!(n, 0, "guard should close without answering");
}
