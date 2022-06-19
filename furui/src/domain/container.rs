use std::convert::TryInto;
use std::net::IpAddr;
use std::sync::Arc;

use aya_bpf::cty::c_char;
use tokio::sync::Mutex;

use furui_common::CONTAINER_ID_LEN;

#[derive(Debug, Clone)]
pub struct Container {
    pub id: Option<String>,
    pub ip_addresses: Option<Vec<IpAddr>>,
    pub name: String,
    pub pid: i64,
}

impl Container {
    pub fn new(id: String) -> Container {
        Container {
            id: Some(id),
            ip_addresses: None,
            name: "".to_string(),
            pid: 0,
        }
    }

    pub fn id(&self) -> [c_char; CONTAINER_ID_LEN] {
        self.id.as_ref().unwrap().as_bytes().try_into().unwrap()
    }
}

#[derive(Debug, Clone)]
pub struct Containers {
    containers: Vec<Container>,
}

impl Containers {
    pub fn new() -> Arc<Mutex<Containers>> {
        Arc::new(Mutex::new(Containers { containers: vec![] }))
    }

    pub fn list(&self) -> Vec<Container> {
        self.containers.clone()
    }

    pub fn add(&mut self, container: Container) {
        self.containers.push(container)
    }

    pub fn get_container_by_name(&self, name: &str) -> Option<Container> {
        for container in &self.containers {
            let mut container_name = container.name.clone();

            container_name.remove(0);

            if container_name == name {
                return Some(container.clone());
            }
        }
        None
    }
}
