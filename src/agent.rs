use std::sync::Arc;

use ssh_agent_lib::agent::Session;
use ssh_agent_lib::error::AgentError;
use ssh_agent_lib::proto::{Identity, SignRequest};
use ssh_key::Signature;
use tokio::sync::RwLock;

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

    async fn sign(&mut self, _request: SignRequest) -> Result<Signature, AgentError> {
        Err(AgentError::from(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "signing not yet implemented",
        )))
    }
}
