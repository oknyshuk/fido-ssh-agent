use std::sync::Arc;

use ctap_hid_fido2::HidParam;
use secrecy::{ExposeSecret, SecretString};
use ssh_agent_lib::agent::Session;
use ssh_agent_lib::error::AgentError;
use ssh_agent_lib::proto::{Identity, SignRequest};
use ssh_key::{Algorithm, Signature};
use tokio::sync::RwLock;

use crate::cache::CredentialCache;

#[derive(Clone)]
pub struct FidoAgent {
    pub(crate) cache: Arc<RwLock<CredentialCache>>,
    pub(crate) upstream: Option<Arc<str>>,
}

impl FidoAgent {
    pub fn new(cache: Arc<RwLock<CredentialCache>>, upstream: Option<String>) -> Self {
        Self {
            cache,
            upstream: upstream.map(Into::into),
        }
    }
}

#[ssh_agent_lib::async_trait]
impl Session for FidoAgent {
    async fn request_identities(&mut self) -> Result<Vec<Identity>, AgentError> {
        let cache = self.cache.read().await;
        let mut ids = cache.identities();
        if let Some(ref upstream) = self.upstream {
            match crate::upstream::list_identities(upstream).await {
                Ok(upstream_ids) => {
                    // Deduplicate: skip upstream keys already served from FIDO cache
                    ids.extend(
                        upstream_ids
                            .into_iter()
                            .filter(|id| cache.lookup(&id.pubkey).is_none()),
                    );
                }
                Err(e) => eprintln!("[WARN] upstream agent: {e:#}"),
            }
        }
        Ok(ids)
    }

    async fn sign(&mut self, request: SignRequest) -> Result<Signature, AgentError> {
        let fido_entry = {
            let cache = self.cache.read().await;
            cache.lookup(&request.pubkey).map(|e| {
                (
                    e.credential_id.clone(),
                    e.application.clone(),
                    e.device_param.clone(),
                )
            })
        };

        let Some((credential_id, application, device_param)) = fido_entry else {
            // Not a FIDO key - forward to upstream agent
            if let Some(ref upstream) = self.upstream {
                eprintln!(
                    "[INFO] sign request for non-FIDO key ({}) -> upstream",
                    request.pubkey.algorithm(),
                );
                return crate::upstream::sign(
                    upstream,
                    &request.pubkey,
                    &request.data,
                    request.flags,
                )
                .await
                .map_err(|e| AgentError::Other(e.into()));
            }
            eprintln!(
                "[WARN] sign request for unknown key ({})",
                request.pubkey.algorithm()
            );
            return Err(AgentError::other(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "unknown key",
            )));
        };

        // Try cached PIN first
        let cached_pin = self.cache.read().await.get_pin(&device_param);

        let response = if let Some(pin) = cached_pin {
            eprintln!("[INFO] sign request for {application} - touch key");
            match attempt_assertion(
                &device_param,
                &pin,
                &credential_id,
                &application,
                &request.data,
            )
            .await?
            {
                Ok(resp) => resp,
                Err(e) if crate::ctap::is_pin_error(&e) => {
                    self.cache.write().await.remove_pin(&device_param);
                    eprintln!(
                        "[INFO] cached PIN invalid for {application} - enter PIN and touch key"
                    );
                    let fresh_pin = prompt_pin().await?;
                    let resp = attempt_assertion(
                        &device_param,
                        &fresh_pin,
                        &credential_id,
                        &application,
                        &request.data,
                    )
                    .await?
                    .map_err(|e| {
                        eprintln!("[ERROR] assertion failed: {e:#}");
                        AgentError::Other(e.into())
                    })?;
                    self.cache.write().await.set_pin(&device_param, fresh_pin);
                    resp
                }
                Err(e) => {
                    eprintln!("[ERROR] assertion failed: {e:#}");
                    return Err(AgentError::Other(e.into()));
                }
            }
        } else {
            eprintln!("[INFO] sign request for {application} - enter PIN and touch key");
            let pin = prompt_pin().await?;
            let resp = attempt_assertion(
                &device_param,
                &pin,
                &credential_id,
                &application,
                &request.data,
            )
            .await?
            .map_err(|e| {
                eprintln!("[ERROR] assertion failed: {e:#}");
                AgentError::Other(e.into())
            })?;
            self.cache.write().await.set_pin(&device_param, pin);
            resp
        };

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

async fn attempt_assertion(
    device_param: &HidParam,
    pin: &SecretString,
    credential_id: &[u8],
    application: &str,
    data: &[u8],
) -> Result<Result<crate::ctap::AssertionResponse, anyhow::Error>, AgentError> {
    let param = device_param.clone();
    let pin = SecretString::from(pin.expose_secret().to_string());
    let cred_id = credential_id.to_vec();
    let app = application.to_string();
    let data = data.to_vec();
    tokio::task::spawn_blocking(move || {
        crate::ctap::get_assertion(&param, &pin, &cred_id, &app, &data)
    })
    .await
    .map_err(AgentError::other)
}
