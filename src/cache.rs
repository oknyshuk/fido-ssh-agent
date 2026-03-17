use std::collections::HashMap;

use ctap_hid_fido2::HidParam;
use ssh_agent_lib::proto::Identity;
use ssh_key::PublicKey;
use ssh_key::public::KeyData;

pub struct CredentialEntry {
    pub credential_id: Vec<u8>,
    pub application: String,
    pub public_key: PublicKey,
    pub device_param: HidParam,
}

pub struct CredentialCache {
    entries: HashMap<KeyData, CredentialEntry>,
}

impl CredentialCache {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    pub fn extend(&mut self, entries: impl IntoIterator<Item = CredentialEntry>) {
        self.entries.extend(
            entries
                .into_iter()
                .map(|e| (e.public_key.key_data().clone(), e)),
        );
    }

    pub fn lookup(&self, key_data: &KeyData) -> Option<&CredentialEntry> {
        self.entries.get(key_data)
    }

    pub fn identities(&self) -> Vec<Identity> {
        self.entries
            .values()
            .map(|e| Identity {
                pubkey: e.public_key.key_data().clone(),
                comment: e.application.clone(),
            })
            .collect()
    }

    /// Remove entries whose device_param is not in `active`. Returns count removed.
    pub fn retain_devices(&mut self, active: &[HidParam]) -> usize {
        let before = self.entries.len();
        self.entries
            .retain(|_, e| active.iter().any(|p| hid_param_eq(p, &e.device_param)));
        before - self.entries.len()
    }
}

pub(crate) fn hid_param_eq(a: &HidParam, b: &HidParam) -> bool {
    match (a, b) {
        (HidParam::VidPid { vid: v1, pid: p1 }, HidParam::VidPid { vid: v2, pid: p2 }) => {
            v1 == v2 && p1 == p2
        }
        (HidParam::Path(a), HidParam::Path(b)) => a == b,
        _ => false,
    }
}
