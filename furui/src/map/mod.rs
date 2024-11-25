use std::sync::Arc;

use aya::Ebpf;
pub use container::ContainerMap;
pub use policy::PolicyMap;
pub use process::ProcessMap;
use tokio::sync::Mutex;

mod container;
mod policy;
mod process;

pub struct Maps {
    pub container: ContainerMap,
    pub policy: PolicyMap,
    pub process: ProcessMap,
}

impl Maps {
    pub fn new(bpf: Arc<Mutex<Ebpf>>) -> Arc<Maps> {
        Arc::new(Maps {
            container: ContainerMap::new(bpf.clone()),
            policy: PolicyMap::new(bpf.clone()),
            process: ProcessMap::new(bpf.clone()),
        })
    }
}
