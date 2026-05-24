use std::collections::HashSet;
use std::io;
use std::sync::Arc;

use ctap_hid_fido2::HidParam;
use secrecy::{ExposeSecret, SecretString};
use tokio::net::UnixStream;

use crate::cache::{CredentialCache, DeviceKey};
use crate::proto::{self, Identity, Request, SignRequest};

pub async fn handle_connection(
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
                let known: HashSet<&[u8]> = ids.iter().map(|i| i.key_blob.as_slice()).collect();
                let extra: Vec<Identity> = extra
                    .into_iter()
                    .filter(|i| !known.contains(i.key_blob.as_slice()))
                    .collect();
                drop(known);
                ids.extend(extra);
            }
            Err(e) => eprintln!("[WARN] upstream agent: {e:#}"),
        }
    }
    proto::encode_identities(&ids)
}

async fn sign(cache: &CredentialCache, upstream: Option<&str>, req: SignRequest) -> Vec<u8> {
    let Some((credential_id, application, device)) = cache.lookup(&req.key_blob) else {
        if let Some(path) = upstream {
            eprintln!("[INFO] sign request for non-FIDO key -> upstream");
            match forward_sign_to_upstream(path, &req).await {
                Ok(sig_blob) => return proto::encode_sign_response(&sig_blob),
                Err(e) => eprintln!("[WARN] upstream sign: {e:#}"),
            }
        } else {
            eprintln!("[WARN] sign request for unknown key");
        }
        return proto::encode_failure();
    };

    match sign_with_fido(cache, &device, &credential_id, &application, &req.data).await {
        Ok(resp) => {
            let blob = encode_sk_ed25519_sig(&resp.signature, resp.flags, resp.counter);
            eprintln!(
                "[INFO] signed for {application} (flags=0x{:02x}, counter={})",
                resp.flags, resp.counter,
            );
            proto::encode_sign_response(&blob)
        }
        Err(e) => {
            eprintln!("[ERROR] sign failed: {e:#}");
            proto::encode_failure()
        }
    }
}

/// SK ed25519 signature wire format (RFC 8332 / `PROTOCOL.u2f`):
///
/// ```text
/// string  "sk-ssh-ed25519@openssh.com"
/// string  64-byte raw ed25519 signature
/// u8      flags
/// u32 BE  counter
/// ```
///
/// The `flags` and `counter` bytes are appended raw, *outside* the inner
/// signature `string` — matching `ssh-key`'s `Signature::encode` for
/// `Algorithm::SkEd25519`.
fn encode_sk_ed25519_sig(sig: &[u8], flags: u8, counter: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(40 + sig.len());
    proto::write_string(&mut out, b"sk-ssh-ed25519@openssh.com");
    proto::write_string(&mut out, sig);
    out.push(flags);
    out.extend(counter.to_be_bytes());
    out
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
    let path = || {
        cache
            .current_path(device)
            .ok_or_else(|| anyhow::anyhow!("FIDO device not connected"))
    };

    if let Some(pin) = cache.get_pin(device) {
        eprintln!("[INFO] sign request for {application} - touch key");
        match assert(&path()?, &pin, credential_id, application, data).await {
            Ok(resp) => return Ok(resp),
            Err(e) if crate::ctap::is_pin_error(&e) => {
                cache.remove_pin(device);
                eprintln!("[INFO] cached PIN invalid - enter PIN and touch key");
            }
            Err(e) => return Err(e),
        }
    } else {
        eprintln!("[INFO] sign request for {application} - enter PIN and touch key");
    }

    let pin =
        tokio::task::spawn_blocking(|| crate::pin::request_pin("Enter PIN for FIDO2 security key"))
            .await??;
    let resp = assert(&path()?, &pin, credential_id, application, data).await?;
    cache.set_pin(device, pin);
    Ok(resp)
}

async fn assert(
    param: &HidParam,
    pin: &SecretString,
    credential_id: &[u8],
    application: &str,
    data: &[u8],
) -> anyhow::Result<crate::ctap::AssertionResponse> {
    let param = param.clone();
    let pin = SecretString::from(pin.expose_secret().to_string());
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
    /// The full `SSH_AGENT_SIGN_RESPONSE` wraps this blob in another string,
    /// so it can be re-parsed with the same primitives we use for incoming
    /// frames.
    #[test]
    fn sk_ed25519_sig_layout() {
        let sig = [0x42u8; 64];
        let blob = encode_sk_ed25519_sig(&sig, 0x05, 0xDEAD_BEEF);

        // string "sk-ssh-ed25519@openssh.com"
        assert_eq!(&blob[0..4], &26u32.to_be_bytes());
        assert_eq!(&blob[4..30], b"sk-ssh-ed25519@openssh.com");
        // string 64-byte sig
        assert_eq!(&blob[30..34], &64u32.to_be_bytes());
        assert_eq!(&blob[34..98], &sig);
        // u8 flags || u32 BE counter (raw, not inside a string)
        assert_eq!(blob[98], 0x05);
        assert_eq!(&blob[99..103], &0xDEAD_BEEFu32.to_be_bytes());
        assert_eq!(blob.len(), 103);
    }

    /// `encode_sign_response` wraps the SK blob in `[14][string blob]`.
    /// Round-trip via the same primitives we use for incoming frames.
    #[test]
    fn sign_response_round_trip() {
        let sig = [0xAAu8; 64];
        let blob = encode_sk_ed25519_sig(&sig, 0x01, 7);
        let frame = proto::encode_sign_response(&blob);

        assert_eq!(frame[0], 14); // SSH_AGENT_SIGN_RESPONSE
        let payload_len = u32::from_be_bytes(frame[1..5].try_into().unwrap()) as usize;
        assert_eq!(payload_len, blob.len());
        assert_eq!(&frame[5..], &blob[..]);
    }
}
