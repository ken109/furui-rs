use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use aya_bpf_cty::c_char;
use tokio::sync::Mutex;

use furui_common::CONTAINER_ID_LEN;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Container {
    pub id: Option<String>,
    pub ip_addresses: Option<Vec<IpAddr>>,
    pub name: String,
    pub pid: u32,
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
        match self.id.as_ref() {
            Some(id) => super::string_to_bytes((*id).clone()),
            None => [0; CONTAINER_ID_LEN],
        }
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

    pub fn get(&self, id: String) -> Option<Container> {
        for container in &self.containers {
            let container_id = container.id.clone().unwrap_or("".to_string());

            if id.starts_with(&container_id) {
                return Some(container.clone());
            }
        }
        None
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

    pub fn ids(&self) -> HashMap<String, String> {
        let mut map = HashMap::new();
        for container in &self.containers {
            map.insert(
                container.name.clone().trim_start_matches("/").to_string(),
                container.id.as_ref().unwrap().clone(),
            );
        }
        map
    }

    pub fn remove(&mut self, id: String) {
        for (i, container) in self.containers.clone().iter().enumerate() {
            if id.starts_with(&container.id.clone().unwrap()) {
                self.containers.remove(i);
                break;
            }
        }
    }
}
