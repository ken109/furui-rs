use std::net::IpAddr;

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
}

#[derive(Debug, Clone)]
pub struct Containers {
    containers: Vec<Container>,
}

impl Containers {
    pub fn new() -> Containers {
        Containers { containers: vec![] }
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
