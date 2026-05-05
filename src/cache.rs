use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};

use ctap_hid_fido2::HidParam;
use secrecy::{ExposeSecret, SecretString};
use ssh_agent_lib::proto::Identity;
use ssh_key::PublicKey;
use ssh_key::public::KeyData;

/// Hashable/Eq wrapper for `HidParam`.
#[derive(Clone)]
pub struct DeviceKey(pub HidParam);

impl PartialEq for DeviceKey {
    fn eq(&self, other: &Self) -> bool {
        match (&self.0, &other.0) {
            (HidParam::VidPid { vid: v1, pid: p1 }, HidParam::VidPid { vid: v2, pid: p2 }) => {
                v1 == v2 && p1 == p2
            }
            (HidParam::Path(a), HidParam::Path(b)) => a == b,
            _ => false,
        }
    }
}
impl Eq for DeviceKey {}

impl Hash for DeviceKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match &self.0 {
            HidParam::VidPid { vid, pid } => (0u8, vid, pid).hash(state),
            HidParam::Path(p) => (1u8, p).hash(state),
        }
    }
}

pub struct CredentialEntry {
    pub credential_id: Vec<u8>,
    pub application: String,
    pub public_key: PublicKey,
    pub device: DeviceKey,
}

#[derive(Default)]
pub struct CredentialCache {
    entries: HashMap<KeyData, CredentialEntry>,
    pins: HashMap<DeviceKey, SecretString>,
}

impl CredentialCache {
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

    pub fn set_pin(&mut self, device: &DeviceKey, pin: SecretString) {
        self.pins.insert(device.clone(), pin);
    }

    pub fn get_pin(&self, device: &DeviceKey) -> Option<SecretString> {
        self.pins
            .get(device)
            .map(|p| SecretString::from(p.expose_secret().to_string()))
    }

    pub fn remove_pin(&mut self, device: &DeviceKey) {
        self.pins.remove(device);
    }

    /// Evict entries for devices not in `active`. Returns count of credentials removed.
    pub fn retain_devices(&mut self, active: &HashSet<DeviceKey>) -> usize {
        let before = self.entries.len();
        self.entries.retain(|_, e| active.contains(&e.device));
        self.pins.retain(|k, _| active.contains(k));
        before - self.entries.len()
    }
}
