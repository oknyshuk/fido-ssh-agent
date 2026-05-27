//! systemd-journal priority-prefixed logging.
//!
//! When stderr is captured by systemd-journald (i.e. when running under the
//! socket-activated unit), an `<N>` prefix sets the priority field per
//! `sd-daemon(3)`, enabling `journalctl -p info|warning|err` filtering. On a
//! plain TTY the prefix is harmless noise.
//!
//! Levels we use: `<3>` err, `<4>` warn, `<6>` info.

#[macro_export]
macro_rules! info {
    ($($t:tt)*) => { eprintln!("<6>{}", format_args!($($t)*)) };
}

#[macro_export]
macro_rules! warn_ {
    ($($t:tt)*) => { eprintln!("<4>{}", format_args!($($t)*)) };
}

#[macro_export]
macro_rules! err {
    ($($t:tt)*) => { eprintln!("<3>{}", format_args!($($t)*)) };
}
