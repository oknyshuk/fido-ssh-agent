use std::sync::Arc;

use ssh_agent_lib::agent::Session;
use ssh_agent_lib::error::AgentError;
use ssh_agent_lib::proto::{Identity, SignRequest};
use ssh_key::Signature;
use tokio::sync::RwLock;
use tracing::{debug, error, info};

use crate::cache::CredentialCache;

#[derive(Clone)]
pub struct FidoAgent {
    pub(crate) cache: Arc<RwLock<CredentialCache>>,
}

impl FidoAgent {
    pub fn new(cache: Arc<RwLock<CredentialCache>>) -> Self {
        Self { cache }
    }
}

#[ssh_agent_lib::async_trait]
impl Session for FidoAgent {
    async fn request_identities(&mut self) -> Result<Vec<Identity>, AgentError> {
        let cache = self.cache.read().await;
        Ok(cache.identities())
    }

    async fn sign(&mut self, request: SignRequest) -> Result<Signature, AgentError> {
        let (credential_id, application, device_param) = {
            let cache = self.cache.read().await;
            let entry = cache.lookup(&request.pubkey).ok_or_else(|| {
                AgentError::other(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "unknown key",
                ))
            })?;
            (
                entry.credential_id.clone(),
                entry.application.clone(),
                entry.device_param.clone(),
            )
        };

        info!(application, "sign request — enter PIN and touch key");

        let pin = tokio::task::spawn_blocking(|| {
            crate::pin::request_pin("Enter PIN for FIDO2 security key")
        })
        .await
        .map_err(AgentError::other)?
        .map_err(|e| AgentError::Other(e.into()))?;

        let data = request.data;
        let response = tokio::task::spawn_blocking(move || {
            crate::ctap::get_assertion(&device_param, &pin, &credential_id, &application, &data)
        })
        .await
        .map_err(AgentError::other)?
        .map_err(|e| {
            error!("assertion failed: {e:#}");
            AgentError::Other(e.into())
        })?;

        debug!(
            sig_len = response.signature.len(),
            flags = format!("0x{:02x}", response.flags),
            counter = response.counter,
            "assertion succeeded"
        );

        let sig = crate::sk_sig::encode(&response).map_err(|e| {
            error!("signature encoding failed: {e}");
            AgentError::other(e)
        })?;

        Ok(sig)
    }
}
