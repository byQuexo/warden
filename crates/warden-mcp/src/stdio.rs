//! stdio transport: the gateway spawns a local MCP server (filesystem, git, …) and speaks
//! newline-delimited JSON-RPC over its stdin/stdout. Server→client requests (sampling,
//! elicitation) are answered with an error, exactly like on the HTTP transport.

use std::collections::HashMap;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, Command};
use tokio::sync::{oneshot, Mutex};

use crate::client::ClientError;
use crate::jsonrpc::{self, Message};

/// How to start a stdio MCP server.
#[derive(Clone, Debug)]
pub struct StdioSpec {
    pub command: String,
    pub args: Vec<String>,
    /// Extra environment for the child process (e.g. an API token for that server).
    pub env: Vec<(String, String)>,
}

type Pending = Arc<std::sync::Mutex<HashMap<String, oneshot::Sender<Value>>>>;

pub(crate) struct StdioConn {
    stdin: Mutex<ChildStdin>,
    pending: Pending,
    blocked: Arc<std::sync::Mutex<Vec<String>>>,
    alive: Arc<AtomicBool>,
    _child: Mutex<Child>,
}

impl StdioConn {
    pub(crate) async fn spawn(spec: &StdioSpec) -> Result<Arc<Self>, ClientError> {
        let mut child = Command::new(&spec.command)
            .args(&spec.args)
            .envs(spec.env.iter().map(|(k, v)| (k.as_str(), v.as_str())))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| ClientError::Http(format!("cannot start `{}`: {e}", spec.command)))?;
        let stdin = child.stdin.take().ok_or_else(|| ClientError::Http("no stdin".into()))?;
        let stdout = child.stdout.take().ok_or_else(|| ClientError::Http("no stdout".into()))?;
        let conn = Arc::new(Self {
            stdin: Mutex::new(stdin),
            pending: Arc::new(std::sync::Mutex::new(HashMap::new())),
            blocked: Arc::new(std::sync::Mutex::new(Vec::new())),
            alive: Arc::new(AtomicBool::new(true)),
            _child: Mutex::new(child),
        });

        let reader = conn.clone();
        tokio::spawn(async move {
            let mut lines = BufReader::new(stdout).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let Ok(msg) = serde_json::from_str::<Value>(&line) else { continue };
                match jsonrpc::classify(&msg) {
                    Message::Request { id, method, .. } => {
                        if let Ok(mut b) = reader.blocked.lock() {
                            b.push(method.to_string());
                        }
                        let reply = jsonrpc::error(id.clone(), jsonrpc::METHOD_NOT_FOUND, "blocked by warden gateway");
                        let _ = reader.write(&reply).await;
                    }
                    Message::Response => {
                        let key = msg.get("id").map(Value::to_string).unwrap_or_default();
                        let tx = reader.pending.lock().ok().and_then(|mut p| p.remove(&key));
                        if let Some(tx) = tx {
                            let _ = tx.send(msg);
                        }
                    }
                    _ => {}
                }
            }
            // Process gone: fail every waiting request.
            reader.alive.store(false, Ordering::SeqCst);
            if let Ok(mut p) = reader.pending.lock() {
                p.clear();
            }
        });
        Ok(conn)
    }

    pub(crate) fn is_alive(&self) -> bool {
        self.alive.load(Ordering::SeqCst)
    }

    async fn write(&self, v: &Value) -> Result<(), ClientError> {
        let mut s = self.stdin.lock().await;
        s.write_all(format!("{v}\n").as_bytes()).await.map_err(|e| ClientError::Http(e.to_string()))?;
        s.flush().await.map_err(|e| ClientError::Http(e.to_string()))
    }

    pub(crate) async fn notify(&self, method: &str, params: Value) -> Result<(), ClientError> {
        self.write(&jsonrpc::notification(method, params)).await
    }

    /// Send a request and wait for its response. Returns the response and any
    /// server→client requests that were blocked meanwhile.
    pub(crate) async fn request(
        &self,
        id: Value,
        method: &str,
        params: Value,
        timeout: Duration,
    ) -> Result<(Value, Vec<String>), ClientError> {
        let (tx, rx) = oneshot::channel();
        if let Ok(mut p) = self.pending.lock() {
            p.insert(id.to_string(), tx);
        }
        self.write(&jsonrpc::request(id, method, params)).await?;
        let resp = tokio::time::timeout(timeout, rx)
            .await
            .map_err(|_| ClientError::Protocol(format!("{method}: no response in time")))?
            .map_err(|_| ClientError::Http("stdio server exited".into()))?;
        let blocked = self.blocked.lock().map(|mut b| std::mem::take(&mut *b)).unwrap_or_default();
        Ok((resp, blocked))
    }
}
