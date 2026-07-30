use std::{collections::HashMap, net::IpAddr, sync::Arc};

use aya_ebpf::cty::c_char;
use furui_common::CONTAINER_ID_LEN;
use tokio::sync::RwLock;

/// A container that is running right now.
///
/// Every field is known: a `Container` only exists once the runtime has told us
/// about it. A policy naming a container that is *not* running is a
/// [`super::PolicyTarget`], which is where "we do not know its id yet" belongs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Container {
    pub id: String,
    pub ip_addresses: Vec<IpAddr>,
    pub name: String,
    pub pid: u32,
}

impl Container {
    /// Creates a container from a runtime-supplied id.
    ///
    /// The id is truncated to [`CONTAINER_ID_LEN`], which is what fits in the
    /// eBPF map keys and what the kernel side reads out of the UTS namespace.
    /// Doing it here means the rest of the crate never sees an id too long to
    /// match.
    pub fn new(id: String) -> Container {
        Container {
            id: id.chars().take(CONTAINER_ID_LEN).collect(),
            ip_addresses: vec![],
            name: String::new(),
            pid: 0,
        }
    }

    /// The id as the eBPF maps key on it.
    pub fn id(&self) -> [c_char; CONTAINER_ID_LEN] {
        super::string_to_c_char_bytes(self.id.clone())
    }

    /// The name without docker's leading `/`, as policies spell it.
    pub fn short_name(&self) -> &str {
        self.name.trim_start_matches('/')
    }
}

#[derive(Debug, Clone, Default)]
pub struct Containers {
    containers: Vec<Container>,
}

impl Containers {
    pub fn new() -> Arc<RwLock<Containers>> {
        Arc::new(RwLock::new(Containers::default()))
    }

    pub fn list(&self) -> Vec<Container> {
        self.containers.clone()
    }

    pub fn add(&mut self, container: Container) {
        self.containers.push(container)
    }

    /// Finds a container by id, accepting a longer id than the stored one.
    ///
    /// Ids are truncated to [`CONTAINER_ID_LEN`] on the way in, but docker and
    /// CRI hand out full-length ids, so callers may pass either.
    pub fn get(&self, id: &str) -> Option<Container> {
        self.containers
            .iter()
            .find(|container| id.starts_with(container.id.as_str()))
            .cloned()
    }

    pub fn get_container_by_name(&self, name: &str) -> Option<Container> {
        self.containers
            .iter()
            .find(|container| container.short_name() == name)
            .cloned()
    }

    /// Maps each running container's name to its id.
    pub fn ids(&self) -> HashMap<String, String> {
        self.containers
            .iter()
            .map(|container| (container.short_name().to_string(), container.id.clone()))
            .collect()
    }

    pub fn remove(&mut self, id: &str) {
        if let Some(index) = self
            .containers
            .iter()
            .position(|container| id.starts_with(container.id.as_str()))
        {
            self.containers.remove(index);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn container(id: &str, name: &str) -> Container {
        Container {
            id: id.to_string(),
            ip_addresses: vec![],
            name: name.to_string(),
            pid: 0,
        }
    }

    fn containers(list: Vec<Container>) -> Containers {
        Containers { containers: list }
    }

    #[test]
    fn truncates_an_id_to_what_the_maps_key_on() {
        assert_eq!(Container::new("a".repeat(64)).id.len(), CONTAINER_ID_LEN);
    }

    #[test]
    fn finds_a_container_by_its_exact_id() {
        let containers = containers(vec![
            container("aaaaaaaaaaaa", "/web"),
            container("bbbbbbbbbbbb", "/db"),
        ]);

        assert_eq!(containers.get("bbbbbbbbbbbb").unwrap().name, "/db");
    }

    #[test]
    fn accepts_a_full_length_id_for_a_truncated_one() {
        let containers = containers(vec![container("aaaaaaaaaaaa", "/web")]);

        assert!(containers
            .get("aaaaaaaaaaaabbbbbbbbbbbbcccccccccccc")
            .is_some());
    }

    #[test]
    fn an_unknown_id_finds_nothing() {
        let containers = containers(vec![container("aaaaaaaaaaaa", "/web")]);

        assert!(containers.get("cccccccccccc").is_none());
    }

    #[test]
    fn looks_a_container_up_by_the_name_a_policy_uses() {
        let containers = containers(vec![container("aaaaaaaaaaaa", "/web")]);

        // Policies name containers without docker's leading slash.
        assert!(containers.get_container_by_name("web").is_some());
        assert!(containers.get_container_by_name("/web").is_none());
    }

    #[test]
    fn an_empty_name_does_not_panic() {
        // `name.remove(0)` used to panic on a container with no name.
        let containers = containers(vec![container("aaaaaaaaaaaa", "")]);

        assert!(containers.get_container_by_name("web").is_none());
        assert!(containers.get_container_by_name("").is_some());
    }

    #[test]
    fn ids_maps_policy_names_to_ids() {
        let containers = containers(vec![
            container("aaaaaaaaaaaa", "/web"),
            container("bbbbbbbbbbbb", "/db"),
        ]);

        let ids = containers.ids();
        assert_eq!(ids.get("web").map(String::as_str), Some("aaaaaaaaaaaa"));
        assert_eq!(ids.get("db").map(String::as_str), Some("bbbbbbbbbbbb"));
    }

    #[test]
    fn removes_only_the_named_container() {
        let mut containers = containers(vec![
            container("aaaaaaaaaaaa", "/web"),
            container("bbbbbbbbbbbb", "/db"),
        ]);

        containers.remove("aaaaaaaaaaaa");

        assert_eq!(containers.list().len(), 1);
        assert_eq!(containers.list()[0].name, "/db");
    }

    #[test]
    fn removing_an_unknown_id_is_a_no_op() {
        let mut containers = containers(vec![container("aaaaaaaaaaaa", "/web")]);

        containers.remove("cccccccccccc");

        assert_eq!(containers.list().len(), 1);
    }
}
