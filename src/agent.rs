use std::collections::HashSet;
use std::sync::Arc;

use ctap_hid_fido2::HidParam;
use secrecy::{ExposeSecret, SecretString};
use ssh_agent_lib::agent::Session;
use ssh_agent_lib::client::Client;
use ssh_agent_lib::error::AgentError;
use ssh_agent_lib::proto::{Identity, SignRequest};
use ssh_key::{Algorithm, Signature};
use tokio::net::UnixStream;

use crate::cache::{CredentialCache, DeviceKey};

#[derive(Clone)]
pub struct FidoAgent {
    cache: Arc<CredentialCache>,
    upstream: Option<Arc<str>>,
}

impl FidoAgent {
    pub fn new(cache: Arc<CredentialCache>, upstream: Option<String>) -> Self {
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
        let path = || {
            self.cache.current_path(device).ok_or_else(|| {
                AgentError::other(std::io::Error::other("FIDO device not connected"))
            })
        };

        if let Some(pin) = self.cache.get_pin(device) {
            eprintln!("[INFO] sign request for {application} - touch key");
            match assert(&path()?, &pin, credential_id, application, data).await {
                Ok(resp) => return Ok(resp),
                Err(e) if crate::ctap::is_pin_error(&e) => {
                    self.cache.remove_pin(device);
                    eprintln!("[INFO] cached PIN invalid - enter PIN and touch key");
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
        let resp = assert(&path()?, &pin, credential_id, application, data)
            .await
            .map_err(|e| {
                eprintln!("[ERROR] assertion failed: {e:#}");
                AgentError::Other(e.into())
            })?;
        self.cache.set_pin(device, pin);
        Ok(resp)
    }
}

#[ssh_agent_lib::async_trait]
impl Session for FidoAgent {
    async fn request_identities(&mut self) -> Result<Vec<Identity>, AgentError> {
        let mut ids = self.cache.identities();
        if self.upstream.is_some() {
            let known: HashSet<_> = ids
                .iter()
                .map(|id| id.credential.key_data().clone())
                .collect();
            let upstream = async {
                let mut client = self.upstream().await?;
                client.request_identities().await
            };
            match upstream.await {
                Ok(upstream_ids) => ids.extend(
                    upstream_ids
                        .into_iter()
                        .filter(|id| !known.contains(id.credential.key_data())),
                ),
                Err(e) => eprintln!("[WARN] upstream agent: {e:#}"),
            }
        }
        Ok(ids)
    }

    async fn sign(&mut self, request: SignRequest) -> Result<Signature, AgentError> {
        let key_data = request.credential.key_data();
        let Some((credential_id, application, device)) = self.cache.lookup(key_data) else {
            if self.upstream.is_some() {
                eprintln!(
                    "[INFO] sign request for non-FIDO key ({}) -> upstream",
                    key_data.algorithm(),
                );
                return self.upstream().await?.sign(request).await;
            }
            eprintln!(
                "[WARN] sign request for unknown key ({})",
                key_data.algorithm()
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
    param: &HidParam,
    pin: &SecretString,
    credential_id: &[u8],
    application: &str,
    data: &[u8],
) -> anyhow::Result<crate::ctap::AssertionResponse> {
    let param = param.clone();
    let pin = SecretString::from(pin.expose_secret().to_string());
    let cred_id = credential_id.to_vec();
    let app = application.to_string();
    let data = data.to_vec();
    tokio::task::spawn_blocking(move || {
        crate::ctap::get_assertion(&param, &pin, &cred_id, &app, &data)
    })
    .await?
}
