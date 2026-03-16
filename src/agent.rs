use ssh_agent_lib::agent::Session;
use ssh_agent_lib::error::AgentError;
use ssh_agent_lib::proto::{Identity, SignRequest};
use ssh_key::Signature;

#[derive(Default, Clone)]
pub struct FidoAgent;

#[ssh_agent_lib::async_trait]
impl Session for FidoAgent {
    async fn request_identities(&mut self) -> Result<Vec<Identity>, AgentError> {
        Ok(vec![])
    }

    async fn sign(&mut self, _request: SignRequest) -> Result<Signature, AgentError> {
        Err(AgentError::from(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "no keys loaded",
        )))
    }
}
