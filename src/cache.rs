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

    #[allow(dead_code)] // Phase 4
    pub fn insert(&mut self, entry: CredentialEntry) {
        self.entries
            .insert(entry.public_key.key_data().clone(), entry);
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

    pub fn len(&self) -> usize {
        self.entries.len()
    }
}
