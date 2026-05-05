use std::sync::Arc;

use secrecy::{ExposeSecret, SecretString};
use ssh_agent_lib::agent::Session;
use ssh_agent_lib::client::Client;
use ssh_agent_lib::error::AgentError;
use ssh_agent_lib::proto::{Identity, SignRequest};
use ssh_key::{Algorithm, Signature};
use tokio::net::UnixStream;
use tokio::sync::RwLock;

use crate::cache::{CredentialCache, DeviceKey};

#[derive(Clone)]
pub struct FidoAgent {
    cache: Arc<RwLock<CredentialCache>>,
    upstream: Option<Arc<str>>,
}

impl FidoAgent {
    pub fn new(cache: Arc<RwLock<CredentialCache>>, upstream: Option<String>) -> Self {
        Self {
            cache,
            upstream: upstream.map(Into::into),
        }
    }

    async fn upstream(&self) -> Result<Client<UnixStream>, AgentError> {
        let path = self
            .upstream
            .as_deref()
            .ok_or_else(|| AgentError::other(std::io::Error::other("no upstream agent")))?;
        let stream = UnixStream::connect(path).await.map_err(AgentError::IO)?;
        Ok(Client::new(stream))
    }

    async fn sign_with_fido(
        &self,
        device: &DeviceKey,
        credential_id: &[u8],
        application: &str,
        data: &[u8],
    ) -> Result<crate::ctap::AssertionResponse, AgentError> {
        if let Some(pin) = self.cache.read().await.get_pin(device) {
            eprintln!("[INFO] sign request for {application} - touch key");
            match assert(device, &pin, credential_id, application, data).await {
                Ok(resp) => return Ok(resp),
                Err(e) if crate::ctap::is_pin_error(&e) => {
                    self.cache.write().await.remove_pin(device);
                    eprintln!(
                        "[INFO] cached PIN invalid for {application} - enter PIN and touch key"
                    );
                }
                Err(e) => {
                    eprintln!("[ERROR] assertion failed: {e:#}");
                    return Err(AgentError::Other(e.into()));
                }
            }
        } else {
            eprintln!("[INFO] sign request for {application} - enter PIN and touch key");
        }

        let pin = prompt_pin().await?;
        let resp = assert(device, &pin, credential_id, application, data)
            .await
            .map_err(|e| {
                eprintln!("[ERROR] assertion failed: {e:#}");
                AgentError::Other(e.into())
            })?;
        self.cache.write().await.set_pin(device, pin);
        Ok(resp)
    }
}

#[ssh_agent_lib::async_trait]
impl Session for FidoAgent {
    async fn request_identities(&mut self) -> Result<Vec<Identity>, AgentError> {
        let cache = self.cache.read().await;
        let mut ids = cache.identities();
        if self.upstream.is_some() {
            let upstream = async {
                let mut client = self.upstream().await?;
                client.request_identities().await
            };
            match upstream.await {
                Ok(upstream_ids) => ids.extend(
                    upstream_ids
                        .into_iter()
                        .filter(|id| cache.lookup(&id.pubkey).is_none()),
                ),
                Err(e) => eprintln!("[WARN] upstream agent: {e:#}"),
            }
        }
        Ok(ids)
    }

    async fn sign(&mut self, request: SignRequest) -> Result<Signature, AgentError> {
        let fido = self.cache.read().await.lookup(&request.pubkey).map(|e| {
            (
                e.credential_id.clone(),
                e.application.clone(),
                e.device.clone(),
            )
        });

        let Some((credential_id, application, device)) = fido else {
            if self.upstream.is_some() {
                eprintln!(
                    "[INFO] sign request for non-FIDO key ({}) -> upstream",
                    request.pubkey.algorithm(),
                );
                return self.upstream().await?.sign(request).await;
            }
            eprintln!(
                "[WARN] sign request for unknown key ({})",
                request.pubkey.algorithm()
            );
            return Err(AgentError::other(std::io::Error::other("unknown key")));
        };

        let response = self
            .sign_with_fido(&device, &credential_id, &application, &request.data)
            .await?;

        let mut sig_data = response.signature;
        sig_data.push(response.flags);
        sig_data.extend(response.counter.to_be_bytes());
        let sig = Signature::new(Algorithm::SkEd25519, sig_data).map_err(|e| {
            eprintln!("[ERROR] signature encoding failed: {e}");
            AgentError::other(e)
        })?;

        eprintln!(
            "[INFO] signed for {application} (flags=0x{:02x}, counter={})",
            response.flags, response.counter,
        );
        Ok(sig)
    }
}

async fn prompt_pin() -> Result<SecretString, AgentError> {
    tokio::task::spawn_blocking(|| crate::pin::request_pin("Enter PIN for FIDO2 security key"))
        .await
        .map_err(AgentError::other)?
        .map_err(|e| AgentError::Other(e.into()))
}

async fn assert(
    device: &DeviceKey,
    pin: &SecretString,
    credential_id: &[u8],
    application: &str,
    data: &[u8],
) -> anyhow::Result<crate::ctap::AssertionResponse> {
    let device = device.clone();
    let pin = SecretString::from(pin.expose_secret().to_string());
    let cred_id = credential_id.to_vec();
    let app = application.to_string();
    let data = data.to_vec();
    tokio::task::spawn_blocking(move || {
        crate::ctap::get_assertion(&device, &pin, &cred_id, &app, &data)
    })
    .await?
}
