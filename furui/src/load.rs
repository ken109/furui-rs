use std::convert::TryInto;

use aya::Bpf;
use aya::programs::{KProbe, SchedClassifier, tc, TcAttachType, TracePoint};
// use aya_log::BpfLogger;
use log::info;

use crate::handle;

pub fn bind(bpf: &mut Bpf) -> Result<(), anyhow::Error> {
    // BpfLogger::init(bpf).unwrap();

    let program_v4: &mut KProbe = bpf.program_mut("bind_v4").unwrap().try_into()?;
    program_v4.load()?;
    program_v4.attach("inet_bind", 0)?;

    let program_v6: &mut KProbe = bpf.program_mut("bind_v6").unwrap().try_into()?;
    program_v6.load()?;
    program_v6.attach("inet6_bind", 0)?;

    handle::bind(bpf)?;

    info!("Bind program loaded.");

    Ok(())
}

pub fn connect(bpf: &mut Bpf) -> Result<(), anyhow::Error> {
    // BpfLogger::init(bpf).unwrap();

    let program_tcp: &mut KProbe = bpf.program_mut("tcp_connect").unwrap().try_into()?;
    program_tcp.load()?;
    program_tcp.attach("tcp_connect", 0)?;

    let program_udp_v4: &mut KProbe = bpf.program_mut("udp_connect_v4").unwrap().try_into()?;
    program_udp_v4.load()?;
    program_udp_v4.attach("udp_send_skb", 0)?;

    let program_udp_v6: &mut KProbe = bpf.program_mut("udp_connect_v6").unwrap().try_into()?;
    program_udp_v6.load()?;
    program_udp_v6.attach("udp_v6_send_skb", 0)?;

    handle::connect(bpf)?;

    info!("Connect program loaded.");

    Ok(())
}

pub fn close(bpf: &mut Bpf) -> Result<(), anyhow::Error> {
    // BpfLogger::init(bpf).unwrap();

    let program: &mut TracePoint = bpf.program_mut("close").unwrap().try_into()?;
    program.load()?;
    program.attach("sched", "sched_process_exit")?;

    info!("Close program loaded.");

    Ok(())
}

pub fn ingress(bpf: &mut Bpf, iface: &str) -> Result<(), anyhow::Error> {
    // BpfLogger::init(bpf).unwrap();

    let _ = tc::qdisc_add_clsact(iface);
    let program: &mut SchedClassifier = bpf.program_mut("ingress").unwrap().try_into()?;
    program.load()?;
    program.attach(iface, TcAttachType::Ingress)?;

    info!("Ingress program loaded.");

    Ok(())
}

pub fn ingress_icmp(bpf: &mut Bpf, iface: &str) -> Result<(), anyhow::Error> {
    // BpfLogger::init(bpf).unwrap();

    let _ = tc::qdisc_add_clsact(iface);
    let program: &mut SchedClassifier = bpf.program_mut("ingress_icmp").unwrap().try_into()?;
    program.load()?;
    program.attach(iface, TcAttachType::Ingress)?;

    info!("Ingress ICMP program loaded.");

    Ok(())
}


pub fn egress(bpf: &mut Bpf, iface: &str) -> Result<(), anyhow::Error> {
    // BpfLogger::init(bpf).unwrap();

    let _ = tc::qdisc_add_clsact(iface);
    let program: &mut SchedClassifier = bpf.program_mut("egress").unwrap().try_into()?;
    program.load()?;
    program.attach(iface, TcAttachType::Egress)?;

    info!("Egress program loaded.");

    Ok(())
}

pub fn egress_icmp(bpf: &mut Bpf, iface: &str) -> Result<(), anyhow::Error> {
    // BpfLogger::init(bpf).unwrap();

    let _ = tc::qdisc_add_clsact(iface);
    let program: &mut SchedClassifier = bpf.program_mut("egress_icmp").unwrap().try_into()?;
    program.load()?;
    program.attach(iface, TcAttachType::Egress)?;

    info!("Egress ICMP program loaded.");

    Ok(())
}
