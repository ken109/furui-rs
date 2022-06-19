use aya::Bpf;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::map::policy::PolicyMap;
pub use container::ContainerMap;

mod container;
mod policy;

pub struct Maps {
    pub container: ContainerMap,
    pub policy: PolicyMap,
}

impl Maps {
    pub fn new(bpf: Arc<Mutex<Bpf>>) -> Maps {
        Maps {
            container: ContainerMap::new(bpf.clone()),
            policy: PolicyMap::new(bpf.clone()),
        }
    }
}
