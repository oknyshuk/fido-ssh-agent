use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use std::time::Duration;

use ctap_hid_fido2::HidParam;
use tokio::sync::{RwLock, mpsc};
use tracing::{debug, info, warn};

use crate::cache::{self, CredentialCache};

/// Start the udev hotplug monitor. Spawns a dedicated OS thread for libudev
/// (not Send) and an async task that reconciles device state on changes.
pub fn start(cache: Arc<RwLock<CredentialCache>>) {
    let (tx, rx) = mpsc::unbounded_channel();

    if let Err(e) = std::thread::Builder::new()
        .name("udev-monitor".into())
        .spawn(move || {
            if let Err(e) = poll_loop(tx) {
                tracing::error!("udev monitor failed: {e}");
            }
        })
    {
        warn!("failed to start udev monitor thread: {e}");
        return;
    }

    tokio::spawn(run(rx, cache));
}

fn poll_loop(tx: mpsc::UnboundedSender<()>) -> std::io::Result<()> {
    let monitor = udev::MonitorBuilder::new()?
        .match_subsystem("hidraw")?
        .listen()?;

    info!("udev monitor started, watching for FIDO devices");

    let mut pollfd = libc::pollfd {
        fd: monitor.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };

    loop {
        let ret = unsafe { libc::poll(&mut pollfd, 1, -1) };
        if ret < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }

        for event in monitor.iter() {
            match event.event_type() {
                udev::EventType::Add | udev::EventType::Remove => {
                    debug!(
                        syspath = ?event.syspath(),
                        action = ?event.event_type(),
                        "hidraw event"
                    );
                    if tx.send(()).is_err() {
                        return Ok(());
                    }
                }
                _ => {}
            }
        }
    }
}

async fn run(mut rx: mpsc::UnboundedReceiver<()>, cache: Arc<RwLock<CredentialCache>>) {
    let mut attempted: Vec<HidParam> = Vec::new();

    // Load credentials from any device already plugged in at startup
    reconcile(&cache, &mut attempted).await;

    while rx.recv().await.is_some() {
        // Debounce: wait for device to settle, then drain rapid-fire events
        tokio::time::sleep(Duration::from_secs(1)).await;
        while rx.try_recv().is_ok() {}

        reconcile(&cache, &mut attempted).await;
    }
}

async fn reconcile(cache: &Arc<RwLock<CredentialCache>>, attempted: &mut Vec<HidParam>) {
    let active = match tokio::task::spawn_blocking(crate::ctap::get_device_params).await {
        Ok(p) => p,
        Err(e) => {
            warn!("failed to scan FIDO devices: {e}");
            return;
        }
    };

    // Evict credentials for removed devices
    {
        let mut w = cache.write().await;
        let removed = w.retain_devices(&active);
        if removed > 0 {
            info!("evicted {removed} credential(s) for removed device");
        }
    }

    // Forget attempted state for removed devices
    attempted.retain(|p| active.iter().any(|a| cache::hid_param_eq(a, p)));

    // Load credentials for new devices
    for param in active {
        if attempted.iter().any(|p| cache::hid_param_eq(p, &param)) {
            continue;
        }

        attempted.push(param.clone());

        info!("new FIDO device detected, loading credentials");
        match crate::load_credentials(param).await {
            Ok(entries) => {
                let count = entries.len();
                let mut w = cache.write().await;
                w.extend(entries);
                if count > 0 {
                    info!("loaded {count} credential(s) from new device");
                } else {
                    debug!("device has no SSH credentials");
                }
            }
            Err(e) => {
                warn!("failed to load credentials from new device: {e:#}");
            }
        }
    }
}
