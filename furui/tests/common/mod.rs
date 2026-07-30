//! Helpers for the end-to-end tests.
//!
//! These drive real containers through a real docker daemon and load real eBPF
//! programs, so every test using them is `#[ignore]`d. Run them with
//! `sudo -E cargo test -- --ignored` on a machine where that is acceptable.

use std::{
    process::Command,
    thread,
    time::{Duration, Instant},
};

pub use container::Container;

mod container;

/// Skips the calling test unless it can actually do its job.
///
/// Returns `false` (after printing why) when furui could not attach anyway, so
/// that `cargo test -- --ignored` on a laptop reports a skip rather than a
/// confusing failure.
pub fn can_run() -> bool {
    // SAFETY: `geteuid` is always safe to call.
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("skipping: needs root to attach kprobes and tc classifiers");
        return false;
    }

    match Command::new("docker").arg("info").output() {
        Ok(output) if output.status.success() => true,
        _ => {
            eprintln!("skipping: needs a reachable docker daemon");
            false
        }
    }
}

/// A command whose success or failure the policy is expected to determine.
pub struct Probe<'a> {
    pub what: &'a str,
    pub command: Vec<&'a str>,
    /// Run inside the container rather than on the host.
    pub in_container: bool,
}

impl Probe<'_> {
    fn run(&self, container_id: &str) -> bool {
        let mut argv: Vec<&str> = vec![];
        if self.in_container {
            argv.extend(["docker", "exec", container_id]);
        }
        argv.extend(self.command.iter().copied());

        Command::new(argv[0])
            .args(&argv[1..])
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    }

    /// Asserts the probe's outcome, naming what was being checked on failure.
    pub fn assert(&self, container_id: &str, expected: bool) {
        let actual = self.run(container_id);
        assert_eq!(
            actual,
            expected,
            "{}: expected {}, got {}",
            self.what,
            if expected { "allowed" } else { "blocked" },
            if actual { "allowed" } else { "blocked" },
        );
    }

    /// Polls until the probe reports `expected`, then asserts it.
    ///
    /// Used where the outcome is expected to change on its own -- a container
    /// still starting up, or tc classifiers that have just been attached --
    /// rather than sleeping for a guessed interval.
    pub fn assert_eventually(&self, container_id: &str, expected: bool, within: Duration) {
        let deadline = Instant::now() + within;
        while Instant::now() < deadline {
            if self.run(container_id) == expected {
                break;
            }
            thread::sleep(Duration::from_millis(250));
        }
        self.assert(container_id, expected);
    }
}
