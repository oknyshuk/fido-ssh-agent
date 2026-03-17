use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use ctap_hid_fido2::HidParam;
use secrecy::{ExposeSecret, SecretString};
use tokio::sync::RwLock;

mod agent;
mod cache;
mod ctap;
mod pin;
mod udev;

const MAX_PIN_ATTEMPTS: u32 = 3;

pub(crate) async fn load_credentials(
    param: HidParam,
    cache: &Arc<RwLock<cache::CredentialCache>>,
) -> Result<Vec<cache::CredentialEntry>> {
    for attempt in 1..=MAX_PIN_ATTEMPTS {
        let pin = tokio::task::spawn_blocking(|| pin::request_pin("Enter PIN for security key"))
            .await??;

        let pin_for_ctap = SecretString::from(pin.expose_secret().to_string());
        let p = param.clone();
        match tokio::task::spawn_blocking(move || ctap::enumerate_credentials(&p, &pin_for_ctap))
            .await?
        {
            Ok(entries) => {
                cache.write().await.set_pin(&param, pin);
                return Ok(entries);
            }
            Err(e) if ctap::is_pin_error(&e) && attempt < MAX_PIN_ATTEMPTS => {
                eprintln!("[WARN] wrong PIN ({attempt}/{MAX_PIN_ATTEMPTS})");
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

fn parse_socket_arg() -> Option<PathBuf> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("--socket") => Some(PathBuf::from(
            args.next().expect("--socket requires a path"),
        )),
        Some("--help" | "-h") => {
            eprintln!("Usage: fido-ssh-agent [--socket PATH]");
            std::process::exit(0);
        }
        Some(other) => {
            eprintln!("unknown argument: {other}");
            eprintln!("Usage: fido-ssh-agent [--socket PATH]");
            std::process::exit(1);
        }
        None => None,
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Suppress println! noise from ctap-hid-fido2 (we log to stderr)
    unsafe {
        let devnull = libc::open(c"/dev/null".as_ptr(), libc::O_WRONLY);
        if devnull >= 0 {
            libc::dup2(devnull, libc::STDOUT_FILENO);
            libc::close(devnull);
        }
    }

    let socket_path = resolve_socket_path(parse_socket_arg())?;
    let cache = Arc::new(RwLock::new(cache::CredentialCache::new()));

    let _ = std::fs::remove_file(&socket_path);
    let listener =
        tokio::net::UnixListener::bind(&socket_path).context("failed to bind agent socket")?;

    eprintln!("[INFO] listening on {}", socket_path.display());

    udev::start(cache.clone());

    ssh_agent_lib::agent::listen(listener, agent::FidoAgent::new(cache)).await?;

    Ok(())
}
