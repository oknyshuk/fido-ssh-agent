use std::path::PathBuf;

use anyhow::{Context, Result};
use argh::FromArgs;
use tracing::info;

mod agent;

/// FIDO2 SSH agent daemon
#[derive(FromArgs)]
struct Args {
    /// path to the agent socket
    #[argh(option)]
    socket: Option<PathBuf>,
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

    let _ = std::fs::remove_file(&socket_path);
    let listener =
        tokio::net::UnixListener::bind(&socket_path).context("failed to bind agent socket")?;

    info!("listening on {}", socket_path.display());

    ssh_agent_lib::agent::listen(listener, agent::FidoAgent).await?;

    Ok(())
}
