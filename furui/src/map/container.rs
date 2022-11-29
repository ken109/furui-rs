use std::convert::TryFrom;
use std::sync::Arc;

use aya::maps::HashMap;
use aya::Bpf;
use tokio::sync::Mutex;

use furui_common::{ContainerID, ContainerIP};

use crate::domain;

pub struct ContainerMap {
    bpf: Arc<Mutex<Bpf>>,
}

impl ContainerMap {
    pub fn new(bpf: Arc<Mutex<Bpf>>) -> ContainerMap {
        ContainerMap { bpf }
    }

    pub async fn save_id_with_ips(
        &self,
        containers: Arc<Mutex<domain::Containers>>,
    ) -> anyhow::Result<()> {
        let mut bpf = self.bpf.lock().await;
        let mut map = HashMap::try_from(bpf.map_mut("CONTAINER_ID_FROM_IPS").unwrap())?;
        for container in containers.lock().await.list() {
            for ip in container.ip_addresses.as_ref().unwrap() {
                map.insert(ContainerIP::new(*ip), ContainerID::new(container.id()), 0)?;
            }
        }

        Ok(())
    }

    pub async fn remove_id_from_ips(&self, container: domain::Container) -> anyhow::Result<()> {
        let mut bpf = self.bpf.lock().await;
        let mut map: HashMap<_, ContainerIP, ContainerID> =
            HashMap::try_from(bpf.map_mut("CONTAINER_ID_FROM_IPS").unwrap())?;

        for ip in container.ip_addresses.unwrap() {
            map.remove(&ContainerIP::new(ip))?;
        }

        Ok(())
    }
}
