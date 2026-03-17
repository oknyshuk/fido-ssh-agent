use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use argh::FromArgs;
use ctap_hid_fido2::HidParam;
use tokio::sync::RwLock;
use tracing::{info, warn};

mod agent;
mod cache;
mod ctap;
mod pin;
mod sk_sig;

/// FIDO2 SSH agent daemon
#[derive(FromArgs)]
struct Args {
    /// path to the agent socket
    #[argh(option)]
    socket: Option<PathBuf>,

    /// load credentials from plugged-in FIDO key at startup
    #[argh(switch)]
    load: bool,
}

fn is_pin_error(err: &anyhow::Error) -> bool {
    let msg = format!("{err:?}");
    msg.contains("CTAP2_ERR_PIN_INVALID") || msg.contains("CTAP2_ERR_PIN_AUTH_INVALID")
}

const MAX_PIN_ATTEMPTS: u32 = 3;

async fn load_credentials(param: HidParam) -> Result<Vec<cache::CredentialEntry>> {
    for attempt in 1..=MAX_PIN_ATTEMPTS {
        let pin =
            tokio::task::spawn_blocking(|| pin::request_pin("Enter PIN for FIDO2 security key"))
                .await??;

        let p = param.clone();
        match tokio::task::spawn_blocking(move || ctap::enumerate_credentials(&p, &pin)).await? {
            Ok(entries) => return Ok(entries),
            Err(e) if is_pin_error(&e) && attempt < MAX_PIN_ATTEMPTS => {
                warn!("wrong PIN ({attempt}/{MAX_PIN_ATTEMPTS})");
            }
            Err(e) => return Err(e),
        }
    }
    unreachable!()
}

fn resolve_socket_path(explicit: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(path) = explicit {
        return Ok(path);
    }
    if let Ok(path) = std::env::var("FIDO_SSH_AGENT_SOCK") {
        return Ok(PathBuf::from(path));
    }
    let runtime_dir = std::env::var("XDG_RUNTIME_DIR").context("XDG_RUNTIME_DIR not set")?;
    Ok(PathBuf::from(runtime_dir).join("fido-ssh-agent.sock"))
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("fido_ssh_agent=info".parse()?),
        )
        .init();

    let args: Args = argh::from_env();
    let socket_path = resolve_socket_path(args.socket)?;
    let cache = Arc::new(RwLock::new(cache::CredentialCache::new()));

    if args.load {
        let params = tokio::task::spawn_blocking(ctap::get_device_params).await?;

        if let Some(param) = params.into_iter().next() {
            let entries = load_credentials(param).await?;
            let mut w = cache.write().await;
            w.extend(entries);
            info!("loaded {} credential(s)", w.len());
        } else {
            info!("no FIDO device found, skipping credential load");
        }
    }

    let _ = std::fs::remove_file(&socket_path);
    let listener =
        tokio::net::UnixListener::bind(&socket_path).context("failed to bind agent socket")?;

    info!("listening on {}", socket_path.display());

    ssh_agent_lib::agent::listen(listener, agent::FidoAgent::new(cache)).await?;

    Ok(())
}
