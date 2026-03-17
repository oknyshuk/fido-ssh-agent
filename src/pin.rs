use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};
use secrecy::SecretString;

fn try_askpass(program: &str, args: &[&str]) -> Result<SecretString> {
    let output = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .with_context(|| format!("failed to run {program}"))?;

    if !output.status.success() {
        bail!("{program} exited with {}", output.status);
    }

    let mut pin = String::from_utf8(output.stdout).context("askpass returned invalid UTF-8")?;
    let trimmed_len = pin.trim_end_matches('\n').len();
    pin.truncate(trimmed_len);

    Ok(SecretString::from(pin))
}

pub fn request_pin(prompt: &str) -> Result<SecretString> {
    if let Ok(askpass) = std::env::var("SSH_ASKPASS") {
        return try_askpass(&askpass, &[prompt]);
    }
    if let Ok(pin) = try_askpass("zenity", &["--password", "--title", prompt]) {
        return Ok(pin);
    }
    if let Ok(pin) = try_askpass("kdialog", &["--password", prompt]) {
        return Ok(pin);
    }
    bail!("no askpass program found — set SSH_ASKPASS or install zenity/kdialog")
}
