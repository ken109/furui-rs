use std::convert::TryInto;
use std::fs;
use std::ops::DerefMut;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;

use anyhow::anyhow;
use aya::programs::{tc, KProbe, Program, SchedClassifier, TcAttachType, TracePoint};
use aya::{include_bytes_aligned, Bpf};
use tokio::sync::Mutex;
use tokio::task;
use tracing::info;

pub fn load_bpf() -> anyhow::Result<Bpf> {
    #[cfg(debug_assertions)]
    let bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/furui"
    ))?;
    #[cfg(not(debug_assertions))]
    let bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/furui"
    ))?;

    Ok(bpf)
}

static SCHED_CLASSIFIERS: [(&str, &str); 1] = [
    ("ingress", "ingress"),
    // ("ingress_icmp", "ingress"),
    // ("egress", "egress"),
    // ("egress_icmp", "egress"),
];

static PIN_DIR: &str = "/sys/fs/bpf/furui-rs/globals";

pub fn attach_programs(bpf: &mut Bpf, iface: &str) -> anyhow::Result<()> {
    let bind_v4: &mut KProbe = bpf.program_mut("bind_v4").unwrap().try_into()?;
    bind_v4.load()?;
    bind_v4.attach("inet_bind", 0)?;

    let bind_v6: &mut KProbe = bpf.program_mut("bind_v6").unwrap().try_into()?;
    bind_v6.load()?;
    bind_v6.attach("inet6_bind", 0)?;

    let tcp_connect: &mut KProbe = bpf.program_mut("tcp_connect").unwrap().try_into()?;
    tcp_connect.load()?;
    tcp_connect.attach("tcp_connect", 0)?;

    let udp_connect_v4: &mut KProbe = bpf.program_mut("udp_connect_v4").unwrap().try_into()?;
    udp_connect_v4.load()?;
    udp_connect_v4.attach("udp_send_skb", 0)?;

    let udp_connect_v6: &mut KProbe = bpf.program_mut("udp_connect_v6").unwrap().try_into()?;
    udp_connect_v6.load()?;
    udp_connect_v6.attach("udp_v6_send_skb", 0)?;

    let close: &mut TracePoint = bpf.program_mut("close").unwrap().try_into()?;
    close.load()?;
    close.attach("sched", "sched_process_exit")?;

    let _ = tc::qdisc_add_clsact(iface);
    fs::create_dir_all(PIN_DIR)?;

    for (name, attach_type) in SCHED_CLASSIFIERS {
        let program = bpf.program_mut(name).unwrap();
        let classifier: &mut SchedClassifier = program.try_into().unwrap();
        classifier.load()?;

        let pin_path = format!("/{}/{}", PIN_DIR, name);
        program.pin(&pin_path)?;

        let args = vec![
            "filter",
            "add",
            "dev",
            iface,
            attach_type,
            "bpf",
            "da",
            "object-pinned",
            &pin_path,
        ];
        Command::new("tc").args(&args).output()?;
    }

    info!("bpf programs attached.");

    Ok(())
}

pub fn detach_programs(iface: &str) {
    let _ = fs::remove_dir_all(PIN_DIR);

    let _ = Command::new("tc")
        .args(&vec!["qdisc", "del", "dev", iface, "clsact"])
        .output();
}
