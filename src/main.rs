use std::os::unix::io::FromRawFd;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use ctap_hid_fido2::HidParam;
use secrecy::{ExposeSecret, SecretString};
use tokio::task::LocalSet;

mod agent;
mod cache;
mod ctap;
mod pin;
mod udev;

const MAX_PIN_ATTEMPTS: u32 = 3;

/// Minimum spacing between PIN dialogs after the previous attempt actually
/// reached the device (success/wrong-PIN/exhausted). Cancels do *not* engage
/// the cooldown — see `clear_prompt`.
const PROMPT_COOLDOWN: Duration = Duration::from_secs(10);

pub(crate) async fn load_credentials(
    device: &cache::DeviceKey,
    param: &HidParam,
    cache: &Arc<cache::CredentialCache>,
) -> Result<Vec<cache::CredentialEntry>> {
    // Silent path: a known device reappearing keeps its cached PIN.
    if let Some(pin) = cache.get_pin(device) {
        let d = device.clone();
        let p = param.clone();
        let pin_arg = SecretString::from(pin.expose_secret().to_string());
        match tokio::task::spawn_blocking(move || ctap::enumerate_credentials(&d, &p, &pin_arg))
            .await?
        {
            Ok(entries) => return Ok(entries),
            Err(e) if ctap::is_pin_error(&e) => {
                cache.remove_pin(device);
                eprintln!("[INFO] cached PIN no longer valid - will prompt");
            }
            Err(e) => return Err(e),
        }
    }

    if !cache.try_prompt(device, PROMPT_COOLDOWN) {
        anyhow::bail!("PIN prompt suppressed (cooldown active)")
    }

    for attempt in 1..=MAX_PIN_ATTEMPTS {
        let pin = tokio::task::spawn_blocking(|| pin::request_pin("Enter PIN for security key"))
            .await?
            .inspect_err(|_| cache.clear_prompt(device))?;

        let d = device.clone();
        let p = param.clone();
        let pin_arg = SecretString::from(pin.expose_secret().to_string());
        match tokio::task::spawn_blocking(move || ctap::enumerate_credentials(&d, &p, &pin_arg))
            .await?
        {
            Ok(entries) => {
                cache.set_pin(device, pin);
                return Ok(entries);
            }
            Err(e) if ctap::is_pin_error(&e) && attempt < MAX_PIN_ATTEMPTS => {
                eprintln!("[WARN] wrong PIN ({attempt}/{MAX_PIN_ATTEMPTS})");
            }
            Err(e) => return Err(e),
        }
    }
    anyhow::bail!("PIN attempts exhausted")
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

fn find_upstream() -> Option<String> {
    if let Ok(path) = std::env::var("FIDO_UPSTREAM_AUTH_SOCK")
        && std::path::Path::new(&path).exists()
    {
        return Some(path);
    }
    let runtime = std::env::var("XDG_RUNTIME_DIR").ok()?;
    ["gcr/ssh", "keyring/ssh", "ssh-agent.socket"]
        .into_iter()
        .map(|s| format!("{runtime}/{s}"))
        .find(|p| std::path::Path::new(p).exists())
}

fn systemd_listener() -> Result<Option<tokio::net::UnixListener>> {
    let mut fds = sd_notify::listen_fds()?;
    let Some(fd) = fds.next() else {
        return Ok(None);
    };
    let std_listener = unsafe { std::os::unix::net::UnixListener::from_raw_fd(fd) };
    std_listener.set_nonblocking(true)?;
    Ok(Some(tokio::net::UnixListener::from_std(std_listener)?))
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

    let listener = if let Some(l) = systemd_listener()? {
        eprintln!("[INFO] using systemd socket activation");
        l
    } else {
        let socket_path = resolve_socket_path(parse_socket_arg())?;
        let _ = std::fs::remove_file(&socket_path);
        let l =
            tokio::net::UnixListener::bind(&socket_path).context("failed to bind agent socket")?;
        eprintln!("[INFO] listening on {}", socket_path.display());
        l
    };

    let upstream = find_upstream();
    if let Some(ref path) = upstream {
        eprintln!("[INFO] upstream agent: {path}");
    }

    let cache = Arc::new(cache::CredentialCache::default());
    let agent = agent::FidoAgent::new(cache.clone(), upstream);

    // udev::AsyncMonitorSocket is !Send — must live on a LocalSet.
    let local = LocalSet::new();
    local.spawn_local(async move {
        if let Err(e) = udev::run(cache).await {
            eprintln!("[ERROR] udev monitor exited: {e:#}");
        }
    });

    let _ = sd_notify::notify(&[sd_notify::NotifyState::Ready]);

    tokio::select! {
        res = ssh_agent_lib::agent::listen(listener, agent) => res?,
        () = local => {}
    }

    Ok(())
}
