//! Invoice issuance limiter ("Invoice Issuance Denial of Service" in the
//! scheme spec): a fresh invoice costs the node a database row, so
//! unauthenticated challenges are bounded per client address and globally.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

const WINDOW: Duration = Duration::from_secs(60);
const MAX_TRACKED_ADDRESSES: usize = 4_096;

pub struct IpLimiter {
    per_ip: usize,
    global: usize,
    by_ip: HashMap<String, VecDeque<Instant>>,
    all: VecDeque<Instant>,
}

impl IpLimiter {
    pub fn new(per_ip: usize, global: usize) -> Self {
        Self {
            per_ip,
            global,
            by_ip: HashMap::new(),
            all: VecDeque::new(),
        }
    }

    /// Records one issuance for `ip` at `now` if both windows have room.
    pub fn admit(&mut self, ip: &str, now: Instant) -> bool {
        prune(&mut self.all, now);
        if self.all.len() >= self.global {
            return false;
        }
        if self.by_ip.len() >= MAX_TRACKED_ADDRESSES {
            self.by_ip.retain(|_, times| {
                prune(times, now);
                !times.is_empty()
            });
        }
        let times = self.by_ip.entry(ip.to_owned()).or_default();
        prune(times, now);
        if times.len() >= self.per_ip {
            return false;
        }
        times.push_back(now);
        self.all.push_back(now);
        true
    }
}

fn prune(times: &mut VecDeque<Instant>, now: Instant) {
    while let Some(front) = times.front() {
        if now.duration_since(*front) >= WINDOW {
            times.pop_front();
        } else {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_per_address_and_globally_within_a_minute() {
        let mut l = IpLimiter::new(2, 3);
        let t0 = Instant::now();
        assert!(l.admit("a", t0));
        assert!(l.admit("a", t0));
        assert!(!l.admit("a", t0), "per-address cap");
        assert!(l.admit("b", t0));
        assert!(!l.admit("c", t0), "global cap");
        assert!(l.admit("a", t0 + Duration::from_secs(61)), "window slid");
    }
}
