use std::convert::TryInto;
use aya::{Bpf, include_bytes_aligned};
use aya::programs::{KProbe, SchedClassifier, tc, TcAttachType, TracePoint};


pub fn bind() -> Result<(), anyhow::Error> {
    #[cfg(debug_assertions)]
        let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/bind"
    ))?;
    #[cfg(not(debug_assertions))]
        let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/bind"
    ))?;
    let program_v4: &mut KProbe = bpf.program_mut("bind_v4").unwrap().try_into()?;
    program_v4.load()?;
    program_v4.attach("inet_bind", 0)?;

    let program_v6: &mut KProbe = bpf.program_mut("bind_v6").unwrap().try_into()?;
    program_v6.load()?;
    program_v6.attach("inet6_bind", 0)?;

    Ok(())
}

pub fn connect() -> Result<(), anyhow::Error> {
    #[cfg(debug_assertions)]
        let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/connect"
    ))?;
    #[cfg(not(debug_assertions))]
        let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/connect"
    ))?;
    let program_tcp: &mut KProbe = bpf.program_mut("tcp_connect").unwrap().try_into()?;
    program_tcp.load()?;
    program_tcp.attach("tcp_connect", 0)?;

    let program_udp_v4: &mut KProbe = bpf.program_mut("udp_connect_v4").unwrap().try_into()?;
    program_udp_v4.load()?;
    program_udp_v4.attach("udp_send_skb", 0)?;

    let program_udp_v6: &mut KProbe = bpf.program_mut("udp_connect_v6").unwrap().try_into()?;
    program_udp_v6.load()?;
    program_udp_v6.attach("udp_v6_send_skb", 0)?;

    Ok(())
}

pub fn close() -> Result<(), anyhow::Error> {
    #[cfg(debug_assertions)]
        let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/close"
    ))?;
    #[cfg(not(debug_assertions))]
        let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/close"
    ))?;
    let program: &mut TracePoint = bpf.program_mut("close").unwrap().try_into()?;
    program.load()?;
    program.attach("sched", "sched_process_exit")?;

    Ok(())
}

pub fn ingress(iface: &str) -> Result<(), anyhow::Error> {
    #[cfg(debug_assertions)]
        let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/ingress"
    ))?;
    #[cfg(not(debug_assertions))]
        let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/ingress"
    ))?;
    let _ = tc::qdisc_add_clsact(iface);
    let program: &mut SchedClassifier = bpf.program_mut("ingress").unwrap().try_into()?;
    program.load()?;
    program.attach(iface, TcAttachType::Ingress)?;

    Ok(())
}

pub fn ingress_icmp(iface: &str) -> Result<(), anyhow::Error> {
    #[cfg(debug_assertions)]
        let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/ingress_icmp"
    ))?;
    #[cfg(not(debug_assertions))]
        let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/ingress_icmp"
    ))?;
    let _ = tc::qdisc_add_clsact(iface);
    let program: &mut SchedClassifier = bpf.program_mut("ingress_icmp").unwrap().try_into()?;
    program.load()?;
    program.attach(iface, TcAttachType::Ingress)?;

    Ok(())
}


pub fn egress(iface: &str) -> Result<(), anyhow::Error> {
    #[cfg(debug_assertions)]
        let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/egress"
    ))?;
    #[cfg(not(debug_assertions))]
        let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/egress"
    ))?;
    let _ = tc::qdisc_add_clsact(iface);
    let program: &mut SchedClassifier = bpf.program_mut("egress").unwrap().try_into()?;
    program.load()?;
    program.attach(iface, TcAttachType::Egress)?;

    Ok(())
}

pub fn egress_icmp(iface: &str) -> Result<(), anyhow::Error> {
    #[cfg(debug_assertions)]
        let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/egress_icmp"
    ))?;
    #[cfg(not(debug_assertions))]
        let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/egress_icmp"
    ))?;
    let _ = tc::qdisc_add_clsact(iface);
    let program: &mut SchedClassifier = bpf.program_mut("egress_icmp").unwrap().try_into()?;
    program.load()?;
    program.attach(iface, TcAttachType::Egress)?;

    Ok(())
}
