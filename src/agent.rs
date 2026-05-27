use std::collections::HashSet;
use std::io;
use std::sync::Arc;

use anyhow::Context;
use ctap_hid_fido2::HidParam;
use secrecy::SecretString;
use tokio::net::UnixStream;

use crate::cache::{CredentialCache, DeviceKey};
use crate::proto::{self, Identity, Request, SignRequest};

pub(crate) async fn handle_connection(
    mut stream: UnixStream,
    cache: Arc<CredentialCache>,
    upstream: Option<Arc<str>>,
) -> io::Result<()> {
    while let Some(frame) = proto::read_frame(&mut stream).await? {
        let resp = match proto::decode_request(&frame)? {
            Request::Identities => identities(&cache, upstream.as_deref()).await,
            Request::Sign(req) => sign(&cache, upstream.as_deref(), req).await,
            Request::Unknown => proto::encode_failure(),
        };
        proto::write_frame(&mut stream, &resp).await?;
    }
    Ok(())
}

async fn identities(cache: &CredentialCache, upstream: Option<&str>) -> Vec<u8> {
    let mut ids = cache.identities();
    if let Some(path) = upstream {
        match fetch_upstream_identities(path).await {
            Ok(extra) => {
                let known: HashSet<Vec<u8>> = ids.iter().map(|i| i.key_blob.clone()).collect();
                ids.extend(extra.into_iter().filter(|i| !known.contains(&i.key_blob)));
            }
            Err(e) => warn_!("upstream agent: {e:#}"),
        }
    }
    proto::encode_identities(&ids)
}

async fn sign(cache: &CredentialCache, upstream: Option<&str>, req: SignRequest) -> Vec<u8> {
    let Some((credential_id, application, device)) = cache.lookup(&req.key_blob) else {
        if let Some(path) = upstream {
            info!("sign request for non-FIDO key -> upstream");
            match forward_sign_to_upstream(path, &req).await {
                Ok(sig_blob) => return proto::encode_sign_response(&sig_blob),
                Err(e) => warn_!("upstream sign: {e:#}"),
            }
        } else {
            warn_!("sign request for unknown key");
        }
        return proto::encode_failure();
    };

    match sign_with_fido(cache, &device, &credential_id, &application, &req.data).await {
        Ok(resp) => {
            let blob = encode_sk_ed25519_sig(&resp.signature, resp.flags, resp.counter);
            info!(
                "signed for {application} (flags=0x{:02x}, counter={})",
                resp.flags, resp.counter,
            );
            proto::encode_sign_response(&blob)
        }
        Err(e) => {
            err!("sign failed: {e:#}");
            proto::encode_failure()
        }
    }
}

async fn fetch_upstream_identities(path: &str) -> io::Result<Vec<Identity>> {
    let mut s = UnixStream::connect(path).await?;
    proto::fetch_identities(&mut s).await
}

async fn forward_sign_to_upstream(path: &str, req: &SignRequest) -> io::Result<Vec<u8>> {
    let mut s = UnixStream::connect(path).await?;
    proto::forward_sign(&mut s, req).await
}

async fn sign_with_fido(
    cache: &CredentialCache,
    device: &DeviceKey,
    credential_id: &[u8],
    application: &str,
    data: &[u8],
) -> anyhow::Result<crate::ctap::AssertionResponse> {
    // Fail fast if the device isn't currently connected. Without this gate
    // we'd happily pop a PIN dialog for a sign request whose target key has
    // been unplugged for hours — e.g. when a background process polls
    // SSH_AUTH_SOCK after the user left their key at home.
    let param = cache
        .current_path(device)
        .context("FIDO device not connected")?;

    if let Some(pin) = cache.get_pin(device) {
        info!("sign request for {application} - touch key");
        match assert(&param, pin.clone(), credential_id, application, data).await {
            Ok(resp) => return Ok(resp),
            Err(e) if crate::ctap::is_pin_error(&e) => {
                cache.remove_pin(device);
                info!("cached PIN invalid - enter PIN and touch key");
            }
            Err(e) => return Err(e),
        }
    } else {
        info!("sign request for {application} - enter PIN and touch key");
    }

    let pin = crate::pin::request_pin("Enter PIN for FIDO2 security key")
        .await
        .map_err(|e| anyhow::anyhow!(e))?;
    let pin = Arc::new(pin);
    // Re-check presence: user may have unplugged while the dialog was up.
    let param = cache
        .current_path(device)
        .context("FIDO device disconnected during PIN entry")?;
    let resp = assert(&param, pin.clone(), credential_id, application, data).await?;
    cache.set_pin(device, pin);
    Ok(resp)
}

/// SK ed25519 signature wire format (`PROTOCOL.u2f`):
///
/// ```text
/// string  "sk-ssh-ed25519@openssh.com"
/// string  64-byte raw ed25519 signature
/// u8      flags
/// u32 BE  counter
/// ```
///
/// The `flags` and `counter` are appended raw, *outside* the inner signature
/// `string` — matches `ssh-key`'s `Signature::encode` for `Algorithm::SkEd25519`.
fn encode_sk_ed25519_sig(sig: &[u8], flags: u8, counter: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(40 + sig.len());
    proto::write_string(&mut out, b"sk-ssh-ed25519@openssh.com");
    proto::write_string(&mut out, sig);
    out.push(flags);
    out.extend(counter.to_be_bytes());
    out
}

async fn assert(
    param: &HidParam,
    pin: Arc<SecretString>,
    credential_id: &[u8],
    application: &str,
    data: &[u8],
) -> anyhow::Result<crate::ctap::AssertionResponse> {
    let param = param.clone();
    let cred_id = credential_id.to_vec();
    let app = application.to_string();
    let data = data.to_vec();
    tokio::task::spawn_blocking(move || {
        crate::ctap::get_assertion(&param, &pin, &cred_id, &app, &data)
    })
    .await?
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte-level assertion that `encode_sk_ed25519_sig` produces exactly the
    /// layout `ssh-key`'s `Signature::encode` would for `Algorithm::SkEd25519`.
    #[test]
    fn sk_ed25519_sig_layout() {
        let sig = [0x42u8; 64];
        let blob = encode_sk_ed25519_sig(&sig, 0x05, 0xDEAD_BEEF);

        assert_eq!(&blob[0..4], &26u32.to_be_bytes());
        assert_eq!(&blob[4..30], b"sk-ssh-ed25519@openssh.com");
        assert_eq!(&blob[30..34], &64u32.to_be_bytes());
        assert_eq!(&blob[34..98], &sig);
        assert_eq!(blob[98], 0x05);
        assert_eq!(&blob[99..103], &0xDEAD_BEEFu32.to_be_bytes());
        assert_eq!(blob.len(), 103);
    }

    #[test]
    fn sign_response_round_trip() {
        let sig = [0xAAu8; 64];
        let blob = encode_sk_ed25519_sig(&sig, 0x01, 7);
        let frame = proto::encode_sign_response(&blob);

        assert_eq!(frame[0], 14);
        let payload_len = u32::from_be_bytes(frame[1..5].try_into().unwrap()) as usize;
        assert_eq!(payload_len, blob.len());
        assert_eq!(&frame[5..], &blob[..]);
    }
}
