use std::convert::TryFrom;
use std::mem::MaybeUninit;
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
            let mut key_uninit = MaybeUninit::<PortKey>::zeroed();
            let mut key_ptr = key_uninit.as_mut_ptr();
            (*key_ptr).container_id = process.container_id();
            (*key_ptr).port = process.port;
            (*key_ptr).proto = process.protocol;

            let mut value_uninit = MaybeUninit::<PortVal>::zeroed();
            let mut value_ptr = value_uninit.as_mut_ptr();
            (*value_ptr).comm = process.executable();

            proc_ports.insert(key_uninit.assume_init(), value_uninit.assume_init(), 0)?;
        }

        Ok(())
    }

    pub async unsafe fn remove(&self, process: Process) -> anyhow::Result<()> {
        let mut proc_ports: HashMap<MapRefMut, PortKey, PortVal> =
            HashMap::try_from(self.bpf.lock().await.map_mut("PROC_PORTS")?)?;

        let mut key_uninit = MaybeUninit::<PortKey>::zeroed();
        let mut key_ptr = key_uninit.as_mut_ptr();
        (*key_ptr).container_id = process.container_id();
        (*key_ptr).port = process.port;
        (*key_ptr).proto = process.protocol;

        proc_ports.remove(key_uninit.assume_init_ref())?;

        Ok(())
    }
}
