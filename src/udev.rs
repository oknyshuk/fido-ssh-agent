use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use ctap_hid_fido2::HidParam;
use futures::StreamExt;
use tokio::time::Instant;
use tokio_udev::{AsyncMonitorSocket, EventType, MonitorBuilder};

use crate::cache::CredentialCache;

/// Window in which we treat clustered hidraw events as a single change. The
/// kernel emits remove+add pairs back-to-back during browser `WebAuthn`
/// re-enumeration; coalescing keeps reconcile work proportional to physical
/// changes, not event volume.
const COALESCE_WINDOW: Duration = Duration::from_millis(750);

pub async fn run(cache: Arc<CredentialCache>) -> Result<()> {
    let mut monitor: AsyncMonitorSocket = MonitorBuilder::new()?
        .match_subsystem("hidraw")?
        .listen()?
        .try_into()?;

    eprintln!("[INFO] udev monitor started, watching for FIDO devices");
    reconcile(&cache).await;

    while let Some(Ok(event)) = monitor.next().await {
        if !matches!(event.event_type(), EventType::Add | EventType::Remove) {
            continue;
        }
        let deadline = Instant::now() + COALESCE_WINDOW;
        while let Ok(Some(_)) = tokio::time::timeout_at(deadline, monitor.next()).await {}
        reconcile(&cache).await;
    }
    Ok(())
}

async fn reconcile(cache: &Arc<CredentialCache>) {
    let visible = match tokio::task::spawn_blocking(crate::ctap::active_devices).await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("[WARN] failed to scan FIDO devices: {e}");
            return;
        }
    };

    cache.refresh_paths(visible.iter().cloned());
    let to_load: Vec<(_, HidParam)> = visible
        .into_iter()
        .filter(|(k, _)| !cache.has_credentials_for(k))
        .collect();

    for (device, param) in to_load {
        eprintln!("[INFO] new FIDO device, loading credentials");
        match crate::load_credentials(&device, &param, cache).await {
            Ok(entries) => {
                let count = entries.len();
                cache.extend(entries);
                if count > 0 {
                    eprintln!("[INFO] loaded {count} credential(s) from new device");
                }
            }
            Err(e) => eprintln!("[WARN] failed to load credentials: {e:#}"),
        }
    }
}
