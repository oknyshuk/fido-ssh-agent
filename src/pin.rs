use std::env;
use std::process::{ExitStatus, Stdio};
use std::time::Duration;

use secrecy::SecretString;
use tokio::process::Command;
use zeroize::Zeroizing;

/// Bundled askpass path baked in by the Nix build via `FIDO_ASKPASS`, falling
/// back to `ssh-askpass` resolved via `PATH` for non-Nix builds. Runtime
/// `SSH_ASKPASS` overrides the bundled default.
const BUNDLED_ASKPASS: &str = match option_env!("FIDO_ASKPASS") {
    Some(p) => p,
    None => "ssh-askpass",
};

/// Hard cap on how long we wait for the user to respond. Prevents the agent
/// from blocking forever if the X server dies mid-prompt or the user walks
/// away with the dialog up.
const ASKPASS_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug)]
pub(crate) enum PinError {
    /// Askpass exited 1 — typical user-cancel. The caller should *not*
    /// engage the prompt cooldown; the user is allowed to retry immediately.
    Canceled,

    /// Askpass exited with a non-1 non-zero code or was killed by a signal.
    /// Distinct from cancel because it usually means the helper is broken
    /// (X died, segfault, etc.) — caller should keep cooldown engaged so a
    /// crash-loop doesn't reprompt every udev burst.
    Crashed(ExitStatus),

    /// Could not spawn the askpass binary at all (not found, permission, etc.).
    Spawn(std::io::Error),

    /// Askpass produced non-UTF-8 bytes on stdout.
    GarbageOutput,

    /// Hit `ASKPASS_TIMEOUT` waiting for output. Child is killed via
    /// `kill_on_drop`.
    Timeout(Duration),
}

impl std::fmt::Display for PinError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Canceled => write!(f, "PIN entry canceled"),
            Self::Crashed(s) => write!(f, "askpass crashed: {s}"),
            Self::Spawn(e) => write!(f, "failed to spawn askpass: {e}"),
            Self::GarbageOutput => write!(f, "askpass returned non-UTF-8 PIN"),
            Self::Timeout(d) => write!(f, "askpass timed out after {d:?}"),
        }
    }
}

impl std::error::Error for PinError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Spawn(e) => Some(e),
            _ => None,
        }
    }
}

impl PinError {
    /// Whether this error should engage the per-device prompt cooldown.
    /// `Canceled` is the user's choice; everything else is a malfunction.
    pub(crate) fn engages_cooldown(&self) -> bool {
        !matches!(self, Self::Canceled)
    }
}

pub(crate) async fn request_pin(prompt: &str) -> Result<SecretString, PinError> {
    let prog = env::var("SSH_ASKPASS").unwrap_or_else(|_| BUNDLED_ASKPASS.into());

    let child = Command::new(&prog)
        .arg(prompt)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(PinError::Spawn)?;

    let out = tokio::time::timeout(ASKPASS_TIMEOUT, child.wait_with_output())
        .await
        .map_err(|_| PinError::Timeout(ASKPASS_TIMEOUT))?
        .map_err(PinError::Spawn)?;

    if !out.status.success() {
        return Err(if out.status.code() == Some(1) {
            PinError::Canceled
        } else {
            PinError::Crashed(out.status)
        });
    }

    let raw = Zeroizing::new(out.stdout);
    let end = raw
        .iter()
        .rposition(|&b| !matches!(b, b'\n' | b'\r'))
        .map_or(0, |i| i + 1);
    let text = std::str::from_utf8(&raw[..end]).map_err(|_| PinError::GarbageOutput)?;
    Ok(SecretString::from(text.to_owned()))
}
