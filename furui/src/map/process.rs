use std::{convert::TryFrom, sync::Arc};

use aya::{maps::HashMap, Ebpf};
use furui_common::{PortKey, PortVal};
use tokio::sync::Mutex;

use crate::domain::Process;

pub struct ProcessMap {
    bpf: Arc<Mutex<Ebpf>>,
}

impl ProcessMap {
    pub fn new(bpf: Arc<Mutex<Ebpf>>) -> ProcessMap {
        ProcessMap { bpf }
    }

    pub async unsafe fn save_all(&self, processes: &Vec<Process>) -> anyhow::Result<()> {
        let mut bpf = self.bpf.lock().await;
        let mut proc_ports = HashMap::try_from(bpf.map_mut("PROC_PORTS").unwrap())?;

        for process in processes {
            let mut key: PortKey = std::mem::zeroed();

            key.container_id = process.container_id();
            key.port = process.port;
            key.proto = process.protocol;

            let mut value: PortVal = std::mem::zeroed();

            value.comm = process.executable();

            proc_ports.insert(key, value, 0)?;
        }

        Ok(())
    }

    pub async unsafe fn remove(&self, process: Process) -> anyhow::Result<()> {
        let mut bpf = self.bpf.lock().await;
        let mut proc_ports: HashMap<_, PortKey, PortVal> =
            HashMap::try_from(bpf.map_mut("PROC_PORTS").unwrap())?;

        let mut key: PortKey = std::mem::zeroed();

        key.container_id = process.container_id();
        key.port = process.port;
        key.proto = process.protocol;

        proc_ports.remove(&key)?;

        Ok(())
    }
}
