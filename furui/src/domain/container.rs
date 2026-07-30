use std::{collections::HashMap, net::IpAddr, sync::Arc};

use aya_ebpf::cty::c_char;
use furui_common::CONTAINER_ID_LEN;
use tokio::sync::RwLock;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Container {
    pub id: Option<String>,
    pub ip_addresses: Option<Vec<IpAddr>>,
    pub name: String,
    pub pid: u32,
}

impl Container {
    /// Creates a container from a runtime-supplied id.
    ///
    /// The id is truncated to [`CONTAINER_ID_LEN`], which is what fits in the
    /// eBPF map keys and what the kernel side reads out of the UTS namespace.
    /// Doing it here means the rest of the crate never sees an id that is too
    /// long to match.
    pub fn new(id: String) -> Container {
        Container {
            id: Some(id.chars().take(CONTAINER_ID_LEN).collect()),
            ip_addresses: None,
            name: "".to_string(),
            pid: 0,
        }
    }

    pub fn id(&self) -> [c_char; CONTAINER_ID_LEN] {
        match self.id.as_ref() {
            Some(id) => super::string_to_c_char_bytes((*id).clone()),
            None => [0; CONTAINER_ID_LEN],
        }
    }

    /// The name without docker's leading `/`, as policies spell it.
    pub fn short_name(&self) -> &str {
        self.name.trim_start_matches('/')
    }
}

#[derive(Debug, Clone)]
pub struct Containers {
    containers: Vec<Container>,
}

impl Containers {
    pub fn new() -> Arc<RwLock<Containers>> {
        Arc::new(RwLock::new(Containers { containers: vec![] }))
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
    pub fn get(&self, id: String) -> Option<Container> {
        self.containers
            .iter()
            .find(|container| {
                // An id-less container must not match: an empty prefix matches
                // every id, which used to return an arbitrary container.
                container
                    .id
                    .as_ref()
                    .is_some_and(|container_id| id.starts_with(container_id.as_str()))
            })
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
            .filter_map(|container| {
                Some((container.short_name().to_string(), container.id.clone()?))
            })
            .collect()
    }

    pub fn remove(&mut self, id: String) {
        if let Some(index) = self.containers.iter().position(|container| {
            container
                .id
                .as_ref()
                .is_some_and(|container_id| id.starts_with(container_id.as_str()))
        }) {
            self.containers.remove(index);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn container(id: Option<&str>, name: &str) -> Container {
        Container {
            id: id.map(str::to_string),
            ip_addresses: None,
            name: name.to_string(),
            pid: 0,
        }
    }

    fn containers(list: Vec<Container>) -> Containers {
        Containers { containers: list }
    }

    #[test]
    fn finds_a_container_by_its_exact_id() {
        let containers = containers(vec![
            container(Some("aaaaaaaaaaaa"), "/web"),
            container(Some("bbbbbbbbbbbb"), "/db"),
        ]);

        assert_eq!(
            containers.get("bbbbbbbbbbbb".to_string()).unwrap().name,
            "/db"
        );
    }

    #[test]
    fn accepts_a_full_length_id_for_a_truncated_one() {
        let containers = containers(vec![container(Some("aaaaaaaaaaaa"), "/web")]);

        assert!(containers
            .get("aaaaaaaaaaaabbbbbbbbbbbbcccccccccccc".to_string())
            .is_some());
    }

    #[test]
    fn an_unknown_id_finds_nothing() {
        let containers = containers(vec![container(Some("aaaaaaaaaaaa"), "/web")]);

        assert!(containers.get("cccccccccccc".to_string()).is_none());
    }

    #[test]
    fn a_container_without_an_id_never_matches() {
        // An absent id used to become an empty prefix, and every id starts with
        // the empty string, so any lookup returned this container.
        let containers = containers(vec![
            container(None, "/pending"),
            container(Some("aaaaaaaaaaaa"), "/web"),
        ]);

        assert_eq!(
            containers.get("aaaaaaaaaaaa".to_string()).unwrap().name,
            "/web"
        );
        assert!(containers.get("cccccccccccc".to_string()).is_none());
    }

    #[test]
    fn looks_a_container_up_by_the_name_a_policy_uses() {
        let containers = containers(vec![container(Some("aaaaaaaaaaaa"), "/web")]);

        // Policies name containers without docker's leading slash.
        assert!(containers.get_container_by_name("web").is_some());
        assert!(containers.get_container_by_name("/web").is_none());
    }

    #[test]
    fn an_empty_name_does_not_panic() {
        // `name.remove(0)` used to panic on a container with no name.
        let containers = containers(vec![container(Some("aaaaaaaaaaaa"), "")]);

        assert!(containers.get_container_by_name("web").is_none());
        assert!(containers.get_container_by_name("").is_some());
    }

    #[test]
    fn ids_maps_policy_names_to_ids() {
        let containers = containers(vec![
            container(Some("aaaaaaaaaaaa"), "/web"),
            container(Some("bbbbbbbbbbbb"), "/db"),
        ]);

        let ids = containers.ids();
        assert_eq!(ids.get("web").map(String::as_str), Some("aaaaaaaaaaaa"));
        assert_eq!(ids.get("db").map(String::as_str), Some("bbbbbbbbbbbb"));
    }

    #[test]
    fn ids_skips_containers_that_have_no_id() {
        // Used to `.unwrap()` and panic.
        let containers = containers(vec![
            container(None, "/pending"),
            container(Some("aaaaaaaaaaaa"), "/web"),
        ]);

        let ids = containers.ids();
        assert_eq!(ids.len(), 1);
        assert!(!ids.contains_key("pending"));
    }

    #[test]
    fn removes_only_the_named_container() {
        let mut containers = containers(vec![
            container(Some("aaaaaaaaaaaa"), "/web"),
            container(Some("bbbbbbbbbbbb"), "/db"),
        ]);

        containers.remove("aaaaaaaaaaaa".to_string());

        assert_eq!(containers.list().len(), 1);
        assert_eq!(containers.list()[0].name, "/db");
    }

    #[test]
    fn removing_an_unknown_id_is_a_no_op() {
        // Used to `.unwrap()` on an id-less container while scanning.
        let mut containers = containers(vec![
            container(None, "/pending"),
            container(Some("aaaaaaaaaaaa"), "/web"),
        ]);

        containers.remove("cccccccccccc".to_string());

        assert_eq!(containers.list().len(), 2);
    }
}
