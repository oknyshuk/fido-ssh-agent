use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use futures::StreamExt;
use tokio::sync::RwLock;
use tokio_udev::{AsyncMonitorSocket, EventType, MonitorBuilder};

use crate::cache::{CredentialCache, DeviceKey};

pub async fn run(cache: Arc<RwLock<CredentialCache>>) -> Result<()> {
    let mut monitor: AsyncMonitorSocket = MonitorBuilder::new()?
        .match_subsystem("hidraw")?
        .listen()?
        .try_into()?;

    eprintln!("[INFO] udev monitor started, watching for FIDO devices");

    let mut attempted: HashSet<DeviceKey> = HashSet::new();
    reconcile(&cache, &mut attempted).await;

    while let Some(Ok(event)) = monitor.next().await {
        if matches!(event.event_type(), EventType::Add | EventType::Remove) {
            // Let the device settle; redundant events during this window
            // produce idempotent reconciles (attempted-set dedups).
            tokio::time::sleep(Duration::from_secs(1)).await;
            reconcile(&cache, &mut attempted).await;
        }
    }
    Ok(())
}

async fn reconcile(cache: &Arc<RwLock<CredentialCache>>, attempted: &mut HashSet<DeviceKey>) {
    let active: HashSet<DeviceKey> =
        match tokio::task::spawn_blocking(crate::ctap::active_devices).await {
            Ok(devs) => devs.into_iter().collect(),
            Err(e) => {
                eprintln!("[WARN] failed to scan FIDO devices: {e}");
                return;
            }
        };

    let removed = cache.write().await.retain_devices(&active);
    if removed > 0 {
        eprintln!("[INFO] evicted {removed} credential(s) for removed device");
    }
    attempted.retain(|d| active.contains(d));

    for device in &active {
        if !attempted.insert(device.clone()) {
            continue;
        }
        eprintln!("[INFO] new FIDO device detected, loading credentials");
        match crate::load_credentials(device.clone(), cache).await {
            Ok(entries) => {
                let count = entries.len();
                cache.write().await.extend(entries);
                if count > 0 {
                    eprintln!("[INFO] loaded {count} credential(s) from new device");
                }
            }
            Err(e) => eprintln!("[WARN] failed to load credentials from new device: {e:#}"),
        }
    }
}
