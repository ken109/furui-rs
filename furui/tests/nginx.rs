//! End-to-end check that a loaded policy actually gates container traffic.
//!
//! Needs root and a docker daemon, hence `#[ignore]`. Run with
//! `sudo -E cargo test -- --ignored`.

use std::{path::PathBuf, time::Duration};

use furui::{ContainerRuntime, LogFormat, LogLevel, Options};

use crate::common::{can_run, Container, Probe};

mod common;

fn policy(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("example")
        .join(name)
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs root and docker"]
async fn nginx_policy_allows_its_port_and_blocks_everything_else() {
    if !can_run() {
        return;
    }

    let nginx = Container::start("nginx_test", "nginx:alpine").await;

    let url = nginx.ipv4_url();
    let serve = Probe {
        what: "host reaching the container's nginx",
        command: vec!["curl", "-sf", "-m", "3", &url],
        in_container: false,
    };
    let egress = Probe {
        what: "container reaching the outside world",
        command: vec![
            "wget",
            "-q",
            "-T",
            "3",
            "-O",
            "/dev/null",
            "http://1.1.1.1/",
        ],
        in_container: true,
    };

    // Without a policy loaded both directions work; asserting this first keeps
    // a broken fixture from looking like successful enforcement. nginx needs a
    // moment to bind port 80.
    serve.assert_eventually(&nginx.id, true, Duration::from_secs(20));
    egress.assert(&nginx.id, true);

    let options = Options {
        container_engine: ContainerRuntime::Docker,
        policy_path: policy("nginx.yaml"),
        log_level: LogLevel::Warn,
        log_fmt: LogFormat::Text,
    };

    // SAFETY: the eBPF object is the one this workspace built.
    unsafe { furui::start(options).await }.expect("failed to start furui");

    // `start` returns once the programs are attached, but the policy is pushed
    // into the maps from spawned tasks.
    egress.assert_eventually(&nginx.id, false, Duration::from_secs(20));
    serve.assert(&nginx.id, true);

    furui::cleanup();
    nginx.remove().await;
}
