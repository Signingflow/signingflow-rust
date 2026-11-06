use std::sync::Mutex;
use std::time::{Duration, SystemTime};

static FIXED_NOW: Mutex<Option<SystemTime>> = Mutex::new(None);
static SLEEP_LOG: Mutex<Option<Vec<Duration>>> = Mutex::new(None);

pub(crate) fn now() -> SystemTime {
    FIXED_NOW.lock().expect("clock").unwrap_or_else(SystemTime::now)
}

pub(crate) fn sleep_for(delay: Duration) {
    let mut log = SLEEP_LOG.lock().expect("sleep");
    if let Some(items) = log.as_mut() {
        items.push(delay);
        return;
    }
    drop(log);
    std::thread::sleep(delay);
}

pub(crate) fn new_uuid() -> String {
    let mut buf = [0u8; 16];
    getrandom::getrandom(&mut buf).expect("random");
    buf[6] = (buf[6] & 0x0f) | 0x40;
    buf[8] = (buf[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15]
    )
}

#[cfg(test)]
pub(crate) fn set_now(instant: Option<SystemTime>) {
    *FIXED_NOW.lock().expect("clock") = instant;
}

#[cfg(test)]
pub(crate) fn record_sleeps() {
    *SLEEP_LOG.lock().expect("sleep") = Some(Vec::new());
}

#[cfg(test)]
pub(crate) fn take_sleeps() -> Vec<Duration> {
    SLEEP_LOG.lock().expect("sleep").take().unwrap_or_default()
}
