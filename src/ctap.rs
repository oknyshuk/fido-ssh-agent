use anyhow::{Context, Result, bail};
use ctap_hid_fido2::fidokey::get_assertion::get_assertion_params::GetAssertionArgsBuilder;
use ctap_hid_fido2::fidokey::get_info::InfoOption;
use ctap_hid_fido2::public_key::PublicKeyType;
use ctap_hid_fido2::{Cfg, FidoKeyHidFactory, HidParam};
use secrecy::{ExposeSecret, SecretString};

use crate::cache::{CredentialEntry, DeviceKey};
use crate::proto::write_string;

/// ctap-hid-fido2 reports CTAP errors as strings formatted by `ctapdef::get_ctap_status_message`,
/// with no structured variants exposed. String-matching is the only option.
pub fn is_pin_error(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        let msg = cause.to_string();
        msg.contains("CTAP2_ERR_PIN_INVALID") || msg.contains("CTAP2_ERR_PIN_AUTH_INVALID")
    })
}

fn cfg() -> Cfg {
    Cfg {
        keep_alive_msg: String::new(),
        ..Cfg::init()
    }
}

pub struct AssertionResponse {
    pub signature: Vec<u8>,
    pub flags: u8,
    pub counter: u32,
}

/// Active FIDO devices paired with the current open handle. Identity is the
/// hidraw path (see `DeviceKey`).
pub fn active_devices() -> Vec<(DeviceKey, HidParam)> {
    ctap_hid_fido2::get_fidokey_devices()
        .into_iter()
        .filter_map(|info| match info.param {
            HidParam::Path(p) => Some((DeviceKey(p.clone()), HidParam::Path(p))),
            HidParam::VidPid { .. } => None,
        })
        .collect()
}

fn open(param: &HidParam) -> Result<ctap_hid_fido2::FidoKeyHid> {
    FidoKeyHidFactory::create_by_params(std::slice::from_ref(param), &cfg())
        .context("failed to open FIDO device")
}

pub fn enumerate_credentials(
    device: &DeviceKey,
    param: &HidParam,
    pin: &SecretString,
) -> Result<Vec<CredentialEntry>> {
    let fido = open(param)?;

    let supports = |opt| matches!(fido.enable_info_option(opt), Ok(Some(true)));
    if !supports(&InfoOption::CredMgmt) && !supports(&InfoOption::CredentialMgmtPreview) {
        bail!("device does not support credential management (requires CTAP 2.1)");
    }

    let rps = fido
        .credential_management_enumerate_rps(Some(pin.expose_secret()))
        .context("failed to enumerate relying parties")?;

    let mut entries = Vec::new();
    for rp in &rps {
        let rp_id = &rp.public_key_credential_rp_entity.id;
        if !rp_id.starts_with("ssh:") {
            continue;
        }

        let creds = fido
            .credential_management_enumerate_credentials(Some(pin.expose_secret()), &rp.rpid_hash)
            .context("failed to enumerate credentials")?;

        for cred in &creds {
            if !matches!(cred.public_key.key_type, PublicKeyType::Ed25519) {
                continue;
            }
            let pubkey_bytes: [u8; 32] = cred
                .public_key
                .der
                .as_slice()
                .try_into()
                .context("expected 32-byte Ed25519 public key")?;
            let mut key_blob = Vec::with_capacity(80);
            write_string(&mut key_blob, b"sk-ssh-ed25519@openssh.com");
            write_string(&mut key_blob, &pubkey_bytes);
            write_string(&mut key_blob, rp_id.as_bytes());
            entries.push(CredentialEntry {
                credential_id: cred.public_key_credential_descriptor.id.clone(),
                application: rp_id.clone(),
                key_blob,
                device: device.clone(),
            });
        }
    }
    Ok(entries)
}

pub fn get_assertion(
    param: &HidParam,
    pin: &SecretString,
    credential_id: &[u8],
    application: &str,
    data: &[u8],
) -> Result<AssertionResponse> {
    let fido = open(param)?;
    let args = GetAssertionArgsBuilder::new(application, data)
        .pin(pin.expose_secret())
        .credential_id(credential_id)
        .build();

    let assertion = fido
        .get_assertion_with_args(&args)
        .context("assertion failed (touch your key if prompted)")?
        .into_iter()
        .next()
        .context("no assertion returned")?;

    Ok(AssertionResponse {
        signature: assertion.signature,
        flags: *assertion.auth_data.get(32).context("auth_data too short")?,
        counter: assertion.sign_count,
    })
}
