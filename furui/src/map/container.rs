use std::convert::TryFrom;
use std::sync::Arc;

use aya::maps::HashMap;
use aya::Bpf;
use tokio::sync::Mutex;

use furui_common::{ContainerID, ContainerIP};

use crate::domain;

pub struct ContainerMap<'a> {
    bpf: &'a mut Bpf,
}

impl ContainerMap<'_> {
    pub fn new(bpf: &mut Bpf) -> ContainerMap {
        ContainerMap { bpf }
    }

    pub async fn save_id_with_ips(
        &self,
        containers: Arc<Mutex<domain::Containers>>,
    ) -> anyhow::Result<()> {
        let mut map = HashMap::try_from(self.bpf.map_mut("CONTAINER_ID_FROM_IPS")?)?;

        for container in containers.lock().await.list() {
            for ip in container.ip_addresses.as_ref().unwrap() {
                map.insert(ContainerIP::new(*ip), ContainerID::new(container.id()), 0)?;
            }
        }

        Ok(())
    }
}
