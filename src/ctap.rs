use anyhow::{Context, Result, bail};
use ctap_hid_fido2::fidokey::get_assertion::get_assertion_params::GetAssertionArgsBuilder;
use ctap_hid_fido2::fidokey::get_info::InfoOption;
use ctap_hid_fido2::public_key::PublicKeyType;
use ctap_hid_fido2::{Cfg, FidoKeyHidFactory, HidParam};
use secrecy::{ExposeSecret, SecretString};
use ssh_key::public::{Ed25519PublicKey, KeyData, SkEd25519};
use tracing::debug;

use crate::cache::CredentialEntry;

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

pub fn get_device_params() -> Vec<HidParam> {
    ctap_hid_fido2::get_fidokey_devices()
        .into_iter()
        .map(|d| d.param)
        .collect()
}

pub fn enumerate_credentials(param: &HidParam, pin: &SecretString) -> Result<Vec<CredentialEntry>> {
    let device = FidoKeyHidFactory::create_by_params(std::slice::from_ref(param), &cfg())
        .context("failed to open FIDO device")?;

    let has_cred_mgmt = matches!(
        device.enable_info_option(&InfoOption::CredMgmt),
        Ok(Some(true))
    );
    let has_cred_mgmt_preview = matches!(
        device.enable_info_option(&InfoOption::CredentialMgmtPreview),
        Ok(Some(true))
    );
    if !has_cred_mgmt && !has_cred_mgmt_preview {
        bail!("device does not support credential management (requires CTAP 2.1)");
    }

    let rps = device
        .credential_management_enumerate_rps(Some(pin.expose_secret()))
        .context("failed to enumerate relying parties")?;

    let mut entries = Vec::new();
    for rp in &rps {
        let rp_id = &rp.public_key_credential_rp_entity.id;
        if !rp_id.starts_with("ssh:") {
            continue;
        }

        let creds = device
            .credential_management_enumerate_credentials(Some(pin.expose_secret()), &rp.rpid_hash)
            .context("failed to enumerate credentials")?;

        for cred in &creds {
            if !matches!(cred.public_key.key_type, PublicKeyType::Ed25519) {
                debug!(
                    rp = rp_id,
                    key_type = ?cred.public_key.key_type,
                    "skipping non-Ed25519 credential"
                );
                continue;
            }

            let pubkey_bytes: [u8; 32] = cred
                .public_key
                .der
                .as_slice()
                .try_into()
                .context("expected 32-byte Ed25519 public key")?;

            let sk_key = SkEd25519::new(Ed25519PublicKey(pubkey_bytes), rp_id.clone());
            let public_key = ssh_key::PublicKey::new(KeyData::SkEd25519(sk_key), "");

            entries.push(CredentialEntry {
                credential_id: cred.public_key_credential_descriptor.id.clone(),
                application: rp_id.clone(),
                public_key,
                device_param: param.clone(),
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
    let device = FidoKeyHidFactory::create_by_params(std::slice::from_ref(param), &cfg())
        .context("failed to open FIDO device")?;

    let args = GetAssertionArgsBuilder::new(application, data)
        .pin(pin.expose_secret())
        .credential_id(credential_id)
        .build();

    let assertions = device
        .get_assertion_with_args(&args)
        .context("assertion failed (touch your key if prompted)")?;

    let assertion = assertions
        .into_iter()
        .next()
        .context("no assertion returned")?;

    let flags = *assertion.auth_data.get(32).context("auth_data too short")?;

    Ok(AssertionResponse {
        signature: assertion.signature,
        flags,
        counter: assertion.sign_count,
    })
}
