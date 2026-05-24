use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use ctap_hid_fido2::HidParam;
use secrecy::{ExposeSecret, SecretString};

use crate::proto::Identity;

/// Stable per-process identity for a FIDO device. The kernel reliably reuses
/// the same `/dev/hidrawN` minor across browser-induced `WebAuthn` re-enum, so
/// path is sufficient. Across suspend/resume or unrelated hidraw churn the
/// path may renumber; the cost is one PIN re-prompt for that device.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DeviceKey(pub String);

pub struct CredentialEntry {
    pub credential_id: Vec<u8>,
    pub application: String,
    /// Canonical SSH wire-encoded `sk-ssh-ed25519@openssh.com` public key.
    pub key_blob: Vec<u8>,
    pub device: DeviceKey,
}

/// Synchronization is internal: every method takes `&self`, locks for one
/// short critical section, returns owned data. Callers never see a guard,
/// so "guard alive across `.await`" deadlocks are structurally impossible.
#[derive(Default)]
pub struct CredentialCache(Mutex<Inner>);

#[derive(Default)]
struct Inner {
    entries: HashMap<Vec<u8>, CredentialEntry>,
    pins: HashMap<DeviceKey, SecretString>,
    /// Refreshed each reconcile; absence means "unplugged", not "evict me".
    paths: HashMap<DeviceKey, HidParam>,
    last_prompt: HashMap<DeviceKey, Instant>,
}

impl CredentialCache {
    fn with<R>(&self, f: impl FnOnce(&mut Inner) -> R) -> R {
        f(&mut self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner))
    }

    pub fn extend(&self, e: impl IntoIterator<Item = CredentialEntry>) {
        self.with(|i| {
            i.entries
                .extend(e.into_iter().map(|c| (c.key_blob.clone(), c)));
        });
    }

    /// `(credential_id, application, device)` for a sign request.
    pub fn lookup(&self, key_blob: &[u8]) -> Option<(Vec<u8>, String, DeviceKey)> {
        self.with(|i| {
            i.entries.get(key_blob).map(|e| {
                (
                    e.credential_id.clone(),
                    e.application.clone(),
                    e.device.clone(),
                )
            })
        })
    }

    pub fn identities(&self) -> Vec<Identity> {
        self.with(|i| {
            i.entries
                .values()
                .map(|e| Identity {
                    key_blob: e.key_blob.clone(),
                    comment: e.application.clone(),
                })
                .collect()
        })
    }

    pub fn has_credentials_for(&self, d: &DeviceKey) -> bool {
        self.with(|i| i.entries.values().any(|e| &e.device == d))
    }

    pub fn current_path(&self, d: &DeviceKey) -> Option<HidParam> {
        self.with(|i| i.paths.get(d).cloned())
    }

    pub fn set_pin(&self, d: &DeviceKey, p: SecretString) {
        self.with(|i| i.pins.insert(d.clone(), p));
    }

    pub fn get_pin(&self, d: &DeviceKey) -> Option<SecretString> {
        self.with(|i| {
            i.pins
                .get(d)
                .map(|p| SecretString::from(p.expose_secret().to_string()))
        })
    }

    pub fn remove_pin(&self, d: &DeviceKey) {
        self.with(|i| i.pins.remove(d));
    }

    pub fn refresh_paths(&self, v: impl IntoIterator<Item = (DeviceKey, HidParam)>) {
        self.with(|i| {
            i.paths = v.into_iter().collect();
            // Reap PINs / cooldown stamps for devices that no longer back any
            // credential and are no longer visible (path renumber across
            // suspend/resume, unrelated hidraw churn).
            let alive: std::collections::HashSet<DeviceKey> = i
                .paths
                .keys()
                .cloned()
                .chain(i.entries.values().map(|e| e.device.clone()))
                .collect();
            i.pins.retain(|k, _| alive.contains(k));
            i.last_prompt.retain(|k, _| alive.contains(k));
        });
    }

    /// Atomic test-and-set on a per-device PIN-dialog rate-limit.
    pub fn try_prompt(&self, d: &DeviceKey, cooldown: Duration) -> bool {
        self.with(|i| {
            let now = Instant::now();
            let allowed = i
                .last_prompt
                .get(d)
                .is_none_or(|t| now.duration_since(*t) >= cooldown);
            if allowed {
                i.last_prompt.insert(d.clone(), now);
            }
            allowed
        })
    }

    /// Release a slot reserved by `try_prompt` (e.g. on user cancel).
    pub fn clear_prompt(&self, d: &DeviceKey) {
        self.with(|i| i.last_prompt.remove(d));
    }
}
