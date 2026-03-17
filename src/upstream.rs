use anyhow::{Result, bail};
use ssh_agent_lib::proto::{Identity, Request, Response, SignRequest};
use ssh_agent_lib::ssh_encoding::{Decode, Encode};
use ssh_key::Signature;
use ssh_key::public::KeyData;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

async fn round_trip(socket: &str, request: &Request) -> Result<Response> {
    let mut payload = Vec::new();
    request
        .encode(&mut payload)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    let mut stream = UnixStream::connect(socket).await?;
    stream
        .write_all(&(payload.len() as u32).to_be_bytes())
        .await?;
    stream.write_all(&payload).await?;

    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let resp_len = u32::from_be_bytes(len_buf) as usize;

    let mut resp_buf = vec![0u8; resp_len];
    stream.read_exact(&mut resp_buf).await?;

    Response::decode(&mut &resp_buf[..]).map_err(|e| anyhow::anyhow!("{e}"))
}

pub async fn list_identities(socket: &str) -> Result<Vec<Identity>> {
    match round_trip(socket, &Request::RequestIdentities).await? {
        Response::IdentitiesAnswer(ids) => Ok(ids),
        _ => bail!("unexpected response from upstream agent"),
    }
}

pub async fn sign(socket: &str, pubkey: &KeyData, data: &[u8], flags: u32) -> Result<Signature> {
    let request = Request::SignRequest(SignRequest {
        pubkey: pubkey.clone(),
        data: data.to_vec(),
        flags,
    });
    match round_trip(socket, &request).await? {
        Response::SignResponse(sig) => Ok(sig),
        Response::Failure => bail!("upstream agent refused to sign"),
        _ => bail!("unexpected response from upstream agent"),
    }
}
