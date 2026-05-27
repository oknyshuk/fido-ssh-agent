use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ctap_hid_fido2::HidParam;
use secrecy::SecretString;

use crate::proto::Identity;

/// Stable per-process identity for a FIDO device. The kernel reliably reuses
/// the same `/dev/hidrawN` minor across browser-induced `WebAuthn` re-enum, so
/// path is sufficient. Across suspend/resume or unrelated hidraw churn the
/// path may renumber; the cost is one PIN re-prompt for that device.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct DeviceKey(pub String);

pub(crate) struct CredentialEntry {
    pub credential_id: Vec<u8>,
    pub application: String,
    /// Canonical SSH wire-encoded `sk-ssh-ed25519@openssh.com` public key.
    pub key_blob: Vec<u8>,
    pub device: DeviceKey,
}

/// Linux `CLOCK_BOOTTIME` reading. Unlike `std::time::Instant`
/// (`CLOCK_MONOTONIC`), this clock advances during suspend, so an 8 h sleep
/// counts as 8 h of "absence" for PIN-eviction purposes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct BootInstant(Duration);

impl BootInstant {
    pub(crate) fn now() -> Self {
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: `ts` is a valid out-pointer; CLOCK_BOOTTIME exists since
        // Linux 2.6.39 (2011), well below our minimum (tokio-udev requires
        // newer kernels anyway).
        let r = unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &raw mut ts) };
        assert_eq!(r, 0, "clock_gettime(CLOCK_BOOTTIME) failed");
        // CLOCK_BOOTTIME is monotonic and non-negative since boot, so these
        // i64→u64/u32 conversions are infallible in practice; we still
        // express that via try_from rather than a silent `as` cast.
        let secs = u64::try_from(ts.tv_sec).expect("CLOCK_BOOTTIME tv_sec negative");
        let nanos = u32::try_from(ts.tv_nsec).expect("CLOCK_BOOTTIME tv_nsec out of range");
        Self(Duration::new(secs, nanos))
    }

    fn saturating_since(self, earlier: Self) -> Duration {
        self.0.checked_sub(earlier.0).unwrap_or_default()
    }

    /// Test-only constructor.
    #[cfg(test)]
    fn from_secs(s: u64) -> Self {
        Self(Duration::from_secs(s))
    }
}

/// Synchronization is internal: every method takes `&self`, locks for one
/// short critical section, returns owned data. Callers never see a guard,
/// so "guard alive across `.await`" deadlocks are structurally impossible.
pub(crate) struct CredentialCache {
    inner: Mutex<Inner>,
    /// Continuous-absence threshold above which a device's cached PIN is
    /// dropped. `Duration::ZERO` disables eviction (today's behavior).
    unplug_grace: Duration,
}

#[derive(Default)]
struct Inner {
    entries: HashMap<Vec<u8>, CredentialEntry>,
    pins: HashMap<DeviceKey, Arc<SecretString>>,
    /// Refreshed each reconcile; absence means "unplugged", not "evict me".
    paths: HashMap<DeviceKey, HidParam>,
    /// First-seen-absent timestamp per device. Cleared when device returns.
    absent_since: HashMap<DeviceKey, BootInstant>,
    /// Per-device PIN-prompt rate-limit, real-time wall clock.
    last_prompt: HashMap<DeviceKey, Instant>,
}

impl CredentialCache {
    pub(crate) fn new(unplug_grace: Duration) -> Self {
        Self {
            inner: Mutex::new(Inner::default()),
            unplug_grace,
        }
    }

    fn with<R>(&self, f: impl FnOnce(&mut Inner) -> R) -> R {
        // Poison recovery is safe here: every field is independent and
        // partial mutation can't break invariants. Crashing the daemon is
        // worse UX than continuing.
        f(&mut self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner))
    }

    pub(crate) fn extend(&self, e: impl IntoIterator<Item = CredentialEntry>) {
        self.with(|i| {
            i.entries
                .extend(e.into_iter().map(|c| (c.key_blob.clone(), c)));
        });
    }

    /// `(credential_id, application, device)` for a sign request.
    pub(crate) fn lookup(&self, key_blob: &[u8]) -> Option<(Vec<u8>, String, DeviceKey)> {
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

    pub(crate) fn identities(&self) -> Vec<Identity> {
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

    pub(crate) fn has_credentials_for(&self, d: &DeviceKey) -> bool {
        self.with(|i| i.entries.values().any(|e| &e.device == d))
    }

    pub(crate) fn current_path(&self, d: &DeviceKey) -> Option<HidParam> {
        self.with(|i| i.paths.get(d).cloned())
    }

    pub(crate) fn set_pin(&self, d: &DeviceKey, p: Arc<SecretString>) {
        self.with(|i| i.pins.insert(d.clone(), p));
    }

    /// Returns the cached PIN if the device hasn't been continuously absent
    /// past the unplug-grace threshold. Lazy eviction: stamping happens in
    /// `refresh_paths`; the actual drop happens here on next read.
    pub(crate) fn get_pin(&self, d: &DeviceKey) -> Option<Arc<SecretString>> {
        self.with(|i| {
            if !self.unplug_grace.is_zero()
                && let Some(absent) = i.absent_since.get(d).copied()
                && BootInstant::now().saturating_since(absent) >= self.unplug_grace
            {
                i.pins.remove(d);
                crate::info!("PIN cleared for {} after sustained absence", d.0);
                return None;
            }
            i.pins.get(d).cloned()
        })
    }

    pub(crate) fn remove_pin(&self, d: &DeviceKey) {
        self.with(|i| i.pins.remove(d));
    }

    pub(crate) fn refresh_paths(&self, v: impl IntoIterator<Item = (DeviceKey, HidParam)>) {
        self.with(|i| {
            let now = BootInstant::now();
            let was_present: std::collections::HashSet<DeviceKey> =
                i.paths.keys().cloned().collect();
            i.paths = v.into_iter().collect();

            // Stamp absence for keys that vanished since the last reconcile.
            for k in was_present {
                if !i.paths.contains_key(&k) {
                    i.absent_since.entry(k).or_insert(now);
                }
            }

            // Sweep: any device whose absence has passed grace gets full
            // eviction. Covers both "returned past grace" (so the next
            // reconcile re-enumerates, prompting for PIN proactively) and
            // "still absent past grace" (don't leak `absent_since` /
            // entries / pins for sessions that are over).
            if !self.unplug_grace.is_zero() {
                let stale: Vec<DeviceKey> = i
                    .absent_since
                    .iter()
                    .filter(|(_, t)| now.saturating_since(**t) >= self.unplug_grace)
                    .map(|(k, _)| k.clone())
                    .collect();
                for k in stale {
                    i.pins.remove(&k);
                    i.entries.retain(|_, e| e.device != k);
                    i.absent_since.remove(&k);
                    crate::info!("PIN cleared for {} after sustained absence", k.0);
                }
            }

            // Clear stamps for devices that returned within grace.
            i.absent_since.retain(|k, _| !i.paths.contains_key(k));

            // last_prompt is real-time; reap stamps for keys that no longer
            // back any credential and aren't visible (path renumber, etc.).
            let alive: std::collections::HashSet<DeviceKey> = i
                .paths
                .keys()
                .cloned()
                .chain(i.entries.values().map(|e| e.device.clone()))
                .collect();
            i.last_prompt.retain(|k, _| alive.contains(k));
        });
    }

    /// Atomic test-and-set on a per-device PIN-dialog rate-limit.
    pub(crate) fn try_prompt(&self, d: &DeviceKey, cooldown: Duration) -> bool {
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
    pub(crate) fn clear_prompt(&self, d: &DeviceKey) {
        self.with(|i| i.last_prompt.remove(d));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dev(s: &str) -> DeviceKey {
        DeviceKey(s.into())
    }

    fn pin(s: &str) -> Arc<SecretString> {
        Arc::new(SecretString::from(s.to_string()))
    }

    #[test]
    fn absent_since_stamped_on_disappearance_and_cleared_on_return() {
        let c = CredentialCache::new(Duration::from_secs(5));

        // Both devices present.
        c.refresh_paths([
            (dev("a"), HidParam::Path("a".into())),
            (dev("b"), HidParam::Path("b".into())),
        ]);
        c.set_pin(&dev("a"), pin("1111"));
        c.set_pin(&dev("b"), pin("2222"));

        // a vanishes.
        c.refresh_paths([(dev("b"), HidParam::Path("b".into()))]);
        c.with(|i| {
            assert!(i.absent_since.contains_key(&dev("a")));
            assert!(!i.absent_since.contains_key(&dev("b")));
        });

        // a returns: stamp cleared.
        c.refresh_paths([
            (dev("a"), HidParam::Path("a".into())),
            (dev("b"), HidParam::Path("b".into())),
        ]);
        c.with(|i| assert!(!i.absent_since.contains_key(&dev("a"))));
    }

    #[test]
    fn get_pin_lazy_evicts_after_grace() {
        let c = CredentialCache::new(Duration::from_secs(5));
        c.refresh_paths([(dev("a"), HidParam::Path("a".into()))]);
        c.set_pin(&dev("a"), pin("1111"));

        // Force "absent_since" to T-10s (past the 5s grace).
        c.with(|i| {
            i.paths.clear();
            let past = BootInstant(BootInstant::now().0 - Duration::from_secs(10));
            i.absent_since.insert(dev("a"), past);
        });

        assert!(c.get_pin(&dev("a")).is_none());
        c.with(|i| assert!(!i.pins.contains_key(&dev("a"))));
    }

    #[test]
    fn get_pin_keeps_pin_within_grace() {
        let c = CredentialCache::new(Duration::from_secs(5));
        c.refresh_paths([(dev("a"), HidParam::Path("a".into()))]);
        c.set_pin(&dev("a"), pin("1111"));

        // Absent for only 2s — under the 5s grace.
        c.with(|i| {
            i.paths.clear();
            let recent = BootInstant(BootInstant::now().0 - Duration::from_secs(2));
            i.absent_since.insert(dev("a"), recent);
        });

        assert!(c.get_pin(&dev("a")).is_some());
    }

    #[test]
    fn grace_zero_disables_eviction() {
        let c = CredentialCache::new(Duration::ZERO);
        c.refresh_paths([(dev("a"), HidParam::Path("a".into()))]);
        c.set_pin(&dev("a"), pin("1111"));
        c.refresh_paths([]); // a vanishes
        // BootInstant::now() − any absent_since is enormous; eviction must NOT fire.
        c.with(|i| {
            i.absent_since
                .insert(dev("a"), BootInstant(Duration::from_secs(0)));
        });
        assert!(c.get_pin(&dev("a")).is_some());
    }

    #[test]
    fn pin_evicted_on_return_after_grace() {
        let c = CredentialCache::new(Duration::from_secs(5));
        c.refresh_paths([(dev("a"), HidParam::Path("a".into()))]);
        c.set_pin(&dev("a"), pin("1111"));
        c.extend([CredentialEntry {
            credential_id: vec![1, 2, 3],
            application: "ssh:".into(),
            key_blob: vec![0xaa],
            device: dev("a"),
        }]);

        // Unplug.
        c.refresh_paths([]);
        // Backdate the absence stamp to simulate >grace elapsed.
        c.with(|i| {
            let past = BootInstant(BootInstant::now().0 - Duration::from_secs(10));
            i.absent_since.insert(dev("a"), past);
        });

        // Replug. PIN *and* credential entries must be evicted so the next
        // reconcile re-enumerates and prompts for PIN proactively.
        c.refresh_paths([(dev("a"), HidParam::Path("a".into()))]);
        c.with(|i| {
            assert!(!i.pins.contains_key(&dev("a")));
            assert!(!i.absent_since.contains_key(&dev("a")));
            assert!(!i.entries.values().any(|e| e.device == dev("a")));
        });
        assert!(c.get_pin(&dev("a")).is_none());
        assert!(!c.has_credentials_for(&dev("a")));
    }

    #[test]
    fn pin_kept_on_return_within_grace() {
        let c = CredentialCache::new(Duration::from_secs(5));
        c.refresh_paths([(dev("a"), HidParam::Path("a".into()))]);
        c.set_pin(&dev("a"), pin("1111"));

        // Unplug.
        c.refresh_paths([]);
        // Backdate the absence stamp to within grace.
        c.with(|i| {
            let recent = BootInstant(BootInstant::now().0 - Duration::from_secs(2));
            i.absent_since.insert(dev("a"), recent);
        });

        // Replug. PIN must survive.
        c.refresh_paths([(dev("a"), HidParam::Path("a".into()))]);
        assert!(c.get_pin(&dev("a")).is_some());
    }

    #[test]
    fn still_absent_past_grace_evicts_state() {
        let c = CredentialCache::new(Duration::from_secs(5));
        c.refresh_paths([(dev("a"), HidParam::Path("a".into()))]);
        c.set_pin(&dev("a"), pin("1111"));
        c.extend([CredentialEntry {
            credential_id: vec![1],
            application: "ssh:".into(),
            key_blob: vec![0xaa],
            device: dev("a"),
        }]);

        // Unplug. absent_since stamped.
        c.refresh_paths([]);
        // Backdate the stamp past grace.
        c.with(|i| {
            let past = BootInstant(BootInstant::now().0 - Duration::from_secs(10));
            i.absent_since.insert(dev("a"), past);
        });

        // Any subsequent reconcile (e.g. unrelated USB churn produces an empty
        // refresh_paths()) must reap state for the still-absent device.
        c.refresh_paths([]);
        c.with(|i| {
            assert!(!i.pins.contains_key(&dev("a")));
            assert!(!i.absent_since.contains_key(&dev("a")));
            assert!(!i.entries.values().any(|e| e.device == dev("a")));
        });
    }

    #[test]
    fn from_secs_test_helper() {
        let a = BootInstant::from_secs(100);
        let b = BootInstant::from_secs(105);
        assert_eq!(b.saturating_since(a), Duration::from_secs(5));
        assert_eq!(a.saturating_since(b), Duration::ZERO);
    }
}
