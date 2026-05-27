use std::os::unix::io::FromRawFd;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use ctap_hid_fido2::HidParam;
use tokio::task::LocalSet;

#[macro_use]
mod log;
mod agent;
mod cache;
mod ctap;
mod pin;
mod proto;
mod udev;

const MAX_PIN_ATTEMPTS: u32 = 3;

/// Minimum spacing between PIN dialogs after the previous attempt actually
/// reached the device (success/wrong-PIN/exhausted). Cancels do *not* engage
/// the cooldown — see `clear_prompt` / `PinError::engages_cooldown`.
const PROMPT_COOLDOWN: Duration = Duration::from_secs(10);

/// Default sustained-absence threshold: if a device sits unplugged for at
/// least this long, its cached PIN is dropped. 0 disables the policy.
const DEFAULT_UNPLUG_GRACE: Duration = Duration::from_secs(5);

pub(crate) async fn load_credentials(
    device: &cache::DeviceKey,
    param: &HidParam,
    cache: &Arc<cache::CredentialCache>,
) -> Result<Vec<cache::CredentialEntry>> {
    // Silent path: a known device reappearing keeps its cached PIN.
    if let Some(pin) = cache.get_pin(device) {
        let d = device.clone();
        let p = param.clone();
        let pin = pin.clone();
        match tokio::task::spawn_blocking(move || ctap::enumerate_credentials(&d, &p, &pin)).await?
        {
            Ok(entries) => return Ok(entries),
            Err(e) if ctap::is_pin_error(&e) => {
                cache.remove_pin(device);
                info!("cached PIN no longer valid - will prompt");
            }
            Err(e) => return Err(e),
        }
    }

    if !cache.try_prompt(device, PROMPT_COOLDOWN) {
        anyhow::bail!("PIN prompt suppressed (cooldown active)")
    }

    for attempt in 1..=MAX_PIN_ATTEMPTS {
        let pin = match pin::request_pin("Enter PIN for security key").await {
            Ok(p) => Arc::new(p),
            Err(e) => {
                if !e.engages_cooldown() {
                    cache.clear_prompt(device);
                }
                return Err(anyhow::anyhow!(e));
            }
        };

        let d = device.clone();
        let p = param.clone();
        let pin_arg = pin.clone();
        match tokio::task::spawn_blocking(move || ctap::enumerate_credentials(&d, &p, &pin_arg))
            .await?
        {
            Ok(entries) => {
                cache.set_pin(device, pin);
                return Ok(entries);
            }
            Err(e) if ctap::is_pin_error(&e) && attempt < MAX_PIN_ATTEMPTS => {
                warn_!("wrong PIN ({attempt}/{MAX_PIN_ATTEMPTS})");
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
        Some("--socket") => match args.next() {
            Some(p) => Some(PathBuf::from(p)),
            None => {
                err!("--socket requires a path");
                std::process::exit(1);
            }
        },
        Some("--help" | "-h") => {
            eprintln!("Usage: fido-ssh-agent [--socket PATH]");
            std::process::exit(0);
        }
        Some(other) => {
            err!("unknown argument: {other}");
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

fn unplug_grace_from_env() -> Duration {
    std::env::var("FIDO_SSH_AGENT_UNPLUG_GRACE_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .map_or(DEFAULT_UNPLUG_GRACE, Duration::from_secs)
}

fn systemd_listener() -> Result<Option<tokio::net::UnixListener>> {
    let mut fds = sd_notify::listen_fds()?;
    let Some(fd) = fds.next() else {
        return Ok(None);
    };
    // SAFETY: `fd` is yielded once by `sd_notify::listen_fds()`, which transfers
    // ownership exactly to this caller per `sd_listen_fds(3)`. We immediately
    // wrap in a typed `UnixListener`, which takes ownership of the fd.
    let std_listener = unsafe { std::os::unix::net::UnixListener::from_raw_fd(fd) };
    std_listener.set_nonblocking(true)?;
    Ok(Some(tokio::net::UnixListener::from_std(std_listener)?))
}

async fn serve(
    listener: tokio::net::UnixListener,
    cache: Arc<cache::CredentialCache>,
    upstream: Option<Arc<str>>,
) -> std::io::Result<()> {
    loop {
        let (stream, _) = listener.accept().await?;
        let cache = cache.clone();
        let upstream = upstream.clone();
        tokio::spawn(async move {
            if let Err(e) = agent::handle_connection(stream, cache, upstream).await {
                warn_!("agent connection: {e:#}");
            }
        });
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let listener = if let Some(l) = systemd_listener()? {
        info!("using systemd socket activation");
        l
    } else {
        let socket_path = resolve_socket_path(parse_socket_arg())?;
        let _ = std::fs::remove_file(&socket_path);
        let l =
            tokio::net::UnixListener::bind(&socket_path).context("failed to bind agent socket")?;
        info!("listening on {}", socket_path.display());
        l
    };

    let upstream = find_upstream();
    if let Some(ref path) = upstream {
        info!("upstream agent: {path}");
    }

    let cache = Arc::new(cache::CredentialCache::new(unplug_grace_from_env()));
    let upstream_arc: Option<Arc<str>> = upstream.map(Into::into);

    // udev::AsyncMonitorSocket is !Send — must live on a LocalSet.
    let local = LocalSet::new();
    local.spawn_local({
        let cache = cache.clone();
        async move {
            if let Err(e) = udev::run(cache).await {
                err!("udev monitor exited: {e:#}");
            }
        }
    });

    let _ = sd_notify::notify(&[sd_notify::NotifyState::Ready]);

    tokio::select! {
        res = serve(listener, cache, upstream_arc) => res?,
        () = local => {}
    }

    Ok(())
}
