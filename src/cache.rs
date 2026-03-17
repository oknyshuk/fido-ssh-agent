use ctap_hid_fido2::HidParam;
use ssh_agent_lib::proto::Identity;
use ssh_key::PublicKey;

pub struct CredentialEntry {
    #[allow(dead_code)] // Phase 3
    pub credential_id: Vec<u8>,
    pub application: String,
    pub public_key: PublicKey,
    #[allow(dead_code)] // Phase 3
    pub device_param: HidParam,
}

/// Small credential set (hardware tokens hold <100 keys), linear search is fine.
pub struct CredentialCache {
    entries: Vec<CredentialEntry>,
}

impl CredentialCache {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    #[allow(dead_code)] // Phase 4
    pub fn insert(&mut self, entry: CredentialEntry) {
        self.entries.push(entry);
    }

    pub fn extend(&mut self, entries: impl IntoIterator<Item = CredentialEntry>) {
        self.entries.extend(entries);
    }

    #[allow(dead_code)] // Phase 3
    pub fn lookup(&self, pubkey: &PublicKey) -> Option<&CredentialEntry> {
        self.entries.iter().find(|e| &e.public_key == pubkey)
    }

    pub fn identities(&self) -> Vec<Identity> {
        self.entries
            .iter()
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
