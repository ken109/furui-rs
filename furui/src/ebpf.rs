use std::{convert::TryInto, process::Command, sync::Arc};

use aya::{
    include_bytes_aligned,
    programs::{tc, KProbe, SchedClassifier, TcAttachType, TracePoint},
    Ebpf,
};
use aya_log::EbpfLogger;
use tokio::sync::Mutex;
use tracing::{debug, info};

pub fn load_bpf() -> anyhow::Result<Arc<Mutex<Ebpf>>> {
    let bpf = Ebpf::load(include_bytes_aligned!(concat!(env!("OUT_DIR"), "/furui")))?;

    Ok(Arc::new(Mutex::new(bpf)))
}

pub struct Loader {
    bpf: Arc<Mutex<Ebpf>>,
}

impl Loader {
    pub fn new(bpf: Arc<Mutex<Ebpf>>) -> Arc<Loader> {
        Arc::new(Loader { bpf })
    }

    pub async fn attach_programs(&self) -> anyhow::Result<()> {
        let mut bpf = self.bpf.lock().await;

        let _ =
            EbpfLogger::init(&mut bpf).map_err(|e| debug!("failed to init EbpfLogger: {:?}", e));

        let program: &mut KProbe = bpf.program_mut("bind_v4").unwrap().try_into()?;
        program.load()?;
        program.attach("inet_bind", 0)?;

        let program: &mut KProbe = bpf.program_mut("bind_v6").unwrap().try_into()?;
        program.load()?;
        program.attach("inet6_bind", 0)?;

        let program: &mut KProbe = bpf.program_mut("tcp_connect").unwrap().try_into()?;
        program.load()?;
        program.attach("tcp_connect", 0)?;

        let program: &mut KProbe = bpf.program_mut("udp_connect_v4").unwrap().try_into()?;
        program.load()?;
        program.attach("udp_send_skb", 0)?;

        let program: &mut KProbe = bpf.program_mut("udp_connect_v6").unwrap().try_into()?;
        program.load()?;
        program.attach("udp_v6_send_skb", 0)?;

        let program: &mut TracePoint = bpf.program_mut("close").unwrap().try_into()?;
        program.load()?;
        program.attach("sched", "sched_process_exit")?;

        let program: &mut SchedClassifier = bpf.program_mut("ingress").unwrap().try_into().unwrap();
        program.load()?;

        let program: &mut SchedClassifier = bpf.program_mut("egress").unwrap().try_into().unwrap();
        program.load()?;

        drop(bpf);

        self.attach_tc_programs().await?;

        info!("bpf programs attached.");

        Ok(())
    }

    pub async fn attach_tc_programs(&self) -> anyhow::Result<()> {
        let mut bpf = self.bpf.lock().await;

        for interface in pnet_datalink::interfaces() {
            if !interface.name.starts_with("veth") {
                continue;
            }
            let iface = interface.name.as_str();

            let _ = tc::qdisc_add_clsact(iface);

            let program: &mut SchedClassifier =
                bpf.program_mut("ingress").unwrap().try_into().unwrap();
            program.attach(iface, TcAttachType::Egress)?;

            let program: &mut SchedClassifier =
                bpf.program_mut("egress").unwrap().try_into().unwrap();
            program.attach(iface, TcAttachType::Ingress)?;
        }

        Ok(())
    }
}

pub fn detach_programs() {
    for interface in pnet_datalink::interfaces() {
        if !interface.name.starts_with("veth") {
            continue;
        }

        let iface = interface.name.as_str();

        let _ = Command::new("tc")
            .args(&vec!["qdisc", "del", "dev", iface, "clsact"])
            .output();
    }
}
