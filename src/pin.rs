use std::io::ErrorKind;
use std::process::{Command, Stdio};

use anyhow::{Result, anyhow, bail};
use secrecy::SecretString;

/// Try to get a PIN from a dialog program.
/// Returns `None` if the program isn't installed (caller should try next).
/// Returns `Some(Ok(pin))` on success, `Some(Err(...))` on user cancel or other failure.
fn try_askpass(program: &str, args: &[&str]) -> Option<Result<SecretString>> {
    let output = match Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
    {
        Ok(o) => o,
        Err(e) if e.kind() == ErrorKind::NotFound => return None,
        Err(e) => return Some(Err(anyhow!(e).context(format!("failed to run {program}")))),
    };

    if !output.status.success() {
        return Some(Err(anyhow!("PIN entry canceled")));
    }

    let mut raw = output.stdout;
    while raw.last() == Some(&b'\n') {
        raw.pop();
    }
    Some(
        String::from_utf8(raw)
            .map(SecretString::from)
            .map_err(Into::into),
    )
}

pub fn request_pin(prompt: &str) -> Result<SecretString> {
    if let Ok(askpass) = std::env::var("SSH_ASKPASS") {
        return match try_askpass(&askpass, &[prompt]) {
            Some(result) => result,
            None => bail!("SSH_ASKPASS program '{askpass}' not found"),
        };
    }
    if let Some(result) = try_askpass("zenity", &["--password", "--title", prompt]) {
        return result;
    }
    if let Some(result) = try_askpass("kdialog", &["--password", prompt]) {
        return result;
    }
    bail!("no askpass program found — set SSH_ASKPASS or install zenity/kdialog")
}
