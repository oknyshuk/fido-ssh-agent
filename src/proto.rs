//! Minimal SSH agent wire protocol.
//!
//! Spec: <https://www.ietf.org/archive/id/draft-miller-ssh-agent-14.html>
//! Frame: `u32 BE length || u8 msg_type || payload`. Strings inside payloads
//! are also length-prefixed (`u32 BE || bytes`). Public-key blobs and
//! signatures are themselves SSH strings, treated as opaque bytes here so we
//! never have to parse foreign key types.
use std::io;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

const SSH_AGENT_FAILURE: u8 = 5;
const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
const SSH_AGENT_SIGN_RESPONSE: u8 = 14;

const MAX_FRAME: usize = 256 * 1024;

/// One identity in `SSH_AGENT_IDENTITIES_ANSWER` (§3.5).
#[derive(Clone)]
pub struct Identity {
    pub key_blob: Vec<u8>,
    pub comment: String,
}

/// Decoded `SSH_AGENTC_SIGN_REQUEST` (§3.6).
pub struct SignRequest {
    pub key_blob: Vec<u8>,
    pub data: Vec<u8>,
    pub flags: u32,
}

/// Server-side decoded request. Only the variants we actually handle are
/// listed; everything else is `Unknown(u8)` and answered with FAILURE.
pub enum Request {
    Identities,
    Sign(SignRequest),
    Unknown,
}

fn read_u8(b: &mut &[u8]) -> io::Result<u8> {
    let (h, t) = b.split_first().ok_or(io::ErrorKind::UnexpectedEof)?;
    *b = t;
    Ok(*h)
}

fn read_u32(b: &mut &[u8]) -> io::Result<u32> {
    if b.len() < 4 {
        return Err(io::ErrorKind::UnexpectedEof.into());
    }
    let (h, t) = b.split_at(4);
    *b = t;
    Ok(u32::from_be_bytes(h.try_into().unwrap()))
}

fn read_string(b: &mut &[u8]) -> io::Result<Vec<u8>> {
    let n = read_u32(b)? as usize;
    if b.len() < n {
        return Err(io::ErrorKind::UnexpectedEof.into());
    }
    let (h, t) = b.split_at(n);
    *b = t;
    Ok(h.to_vec())
}

fn write_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}

pub fn write_string(out: &mut Vec<u8>, s: &[u8]) {
    let len = u32::try_from(s.len()).expect("ssh-string exceeds u32::MAX bytes");
    write_u32(out, len);
    out.extend_from_slice(s);
}

// --- Frame I/O ---------------------------------------------------------------

pub async fn read_frame(s: &mut UnixStream) -> io::Result<Option<Vec<u8>>> {
    let mut len_buf = [0u8; 4];
    match s.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 {
        return Err(io::Error::other("empty agent frame"));
    }
    if len > MAX_FRAME {
        return Err(io::Error::other("oversized agent frame"));
    }
    let mut payload = vec![0u8; len];
    s.read_exact(&mut payload).await?;
    Ok(Some(payload))
}

pub async fn write_frame(s: &mut UnixStream, payload: &[u8]) -> io::Result<()> {
    let len = u32::try_from(payload.len())
        .map_err(|_| io::Error::other("agent frame exceeds u32::MAX bytes"))?;
    s.write_all(&len.to_be_bytes()).await?;
    s.write_all(payload).await?;
    s.flush().await
}

// --- Server: decode requests / encode responses ------------------------------

pub fn decode_request(frame: &[u8]) -> io::Result<Request> {
    let mut b = frame;
    Ok(match read_u8(&mut b)? {
        SSH_AGENTC_REQUEST_IDENTITIES => Request::Identities,
        SSH_AGENTC_SIGN_REQUEST => Request::Sign(SignRequest {
            key_blob: read_string(&mut b)?,
            data: read_string(&mut b)?,
            flags: read_u32(&mut b)?,
        }),
        other => {
            let _ = other;
            Request::Unknown
        }
    })
}

pub fn encode_failure() -> Vec<u8> {
    vec![SSH_AGENT_FAILURE]
}

pub fn encode_identities(ids: &[Identity]) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    out.push(SSH_AGENT_IDENTITIES_ANSWER);
    write_u32(
        &mut out,
        u32::try_from(ids.len()).expect("identity count exceeds u32::MAX"),
    );
    for id in ids {
        write_string(&mut out, &id.key_blob);
        write_string(&mut out, id.comment.as_bytes());
    }
    out
}

pub fn encode_sign_response(signature: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + signature.len());
    out.push(SSH_AGENT_SIGN_RESPONSE);
    write_string(&mut out, signature);
    out
}

// --- Client: round-trip a request to an upstream agent -----------------------

pub async fn fetch_identities(s: &mut UnixStream) -> io::Result<Vec<Identity>> {
    write_frame(s, &[SSH_AGENTC_REQUEST_IDENTITIES]).await?;
    let frame = read_frame(s).await?.ok_or(io::ErrorKind::UnexpectedEof)?;
    let mut b = &frame[..];
    if read_u8(&mut b)? != SSH_AGENT_IDENTITIES_ANSWER {
        return Err(io::Error::other("upstream: unexpected response to IDENT"));
    }
    let n = read_u32(&mut b)? as usize;
    (0..n)
        .map(|_| {
            Ok(Identity {
                key_blob: read_string(&mut b)?,
                comment: String::from_utf8(read_string(&mut b)?)
                    .map_err(|_| io::Error::other("upstream: comment not UTF-8"))?,
            })
        })
        .collect()
}

/// Forward a verbatim `SSH_AGENTC_SIGN_REQUEST` to upstream and return the
/// raw signature blob. We pass the request bytes through unchanged so the
/// upstream gets exactly what the client sent.
pub async fn forward_sign(s: &mut UnixStream, req: &SignRequest) -> io::Result<Vec<u8>> {
    let mut frame = Vec::with_capacity(16 + req.key_blob.len() + req.data.len());
    frame.push(SSH_AGENTC_SIGN_REQUEST);
    write_string(&mut frame, &req.key_blob);
    write_string(&mut frame, &req.data);
    write_u32(&mut frame, req.flags);
    write_frame(s, &frame).await?;

    let resp = read_frame(s).await?.ok_or(io::ErrorKind::UnexpectedEof)?;
    let mut b = &resp[..];
    if read_u8(&mut b)? != SSH_AGENT_SIGN_RESPONSE {
        return Err(io::Error::other("upstream: unexpected response to SIGN"));
    }
    read_string(&mut b)
}
