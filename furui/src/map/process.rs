use std::convert::TryFrom;
use std::sync::Arc;

use aya::maps::{HashMap, MapRefMut};
use aya::Bpf;
use tokio::sync::Mutex;

use furui_common::{PortKey, PortVal};

use crate::domain::Process;

pub struct ProcessMap {
    bpf: Arc<Mutex<Bpf>>,
}

impl ProcessMap {
    pub fn new(bpf: Arc<Mutex<Bpf>>) -> ProcessMap {
        ProcessMap { bpf }
    }

    pub async unsafe fn save_all(&self, processes: &Vec<Process>) -> anyhow::Result<()> {
        let mut proc_ports = HashMap::try_from(self.bpf.lock().await.map_mut("PROC_PORTS")?)?;

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
        let mut proc_ports: HashMap<MapRefMut, PortKey, PortVal> =
            HashMap::try_from(self.bpf.lock().await.map_mut("PROC_PORTS")?)?;

        let mut key: PortKey = std::mem::zeroed();

        key.container_id = process.container_id();
        key.port = process.port;
        key.proto = process.protocol;

        proc_ports.remove(&key)?;

        Ok(())
    }
}
