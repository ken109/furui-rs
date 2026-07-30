use std::{ffi::c_char, net::IpAddr, sync::Arc};

use furui_common::{IcmpVersion, IpProtocol, CONTAINER_ID_LEN, TASK_COMM_LEN};
use tokio::sync::RwLock;

use crate::domain::Containers;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Policies {
    pub(crate) policies: Vec<Policy>,
}

impl Policies {
    /// Re-resolves each policy's container name against what is running.
    ///
    /// Called whenever containers or policies change. A policy whose container
    /// is not running keeps its rules but loses its id, so the keys it expands
    /// to match nothing.
    pub async fn set_container_id(&mut self, containers: Arc<RwLock<Containers>>) {
        let ids = containers.read().await.ids();

        for policy in &mut self.policies {
            if policy.container.name.is_empty() {
                continue;
            }

            policy.container.id = ids.get(&policy.container.name).cloned();
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    pub(crate) container: PolicyTarget,
    pub(crate) communications: Vec<Communication>,
}

/// The container a policy applies to.
///
/// Policies are written against a name and outlive any particular container, so
/// unlike [`super::Container`] the id here is genuinely optional: it is `None`
/// whenever nothing by that name is running.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyTarget {
    pub(crate) name: String,
    pub(crate) id: Option<String>,
}

impl PolicyTarget {
    pub fn new(name: String) -> PolicyTarget {
        PolicyTarget { name, id: None }
    }

    /// The id as the eBPF maps key on it, all zeroes when unresolved.
    pub fn id(&self) -> [c_char; CONTAINER_ID_LEN] {
        match self.id.as_ref() {
            Some(id) => super::string_to_c_char_bytes(id.clone()),
            None => [0; CONTAINER_ID_LEN],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Communication {
    pub(crate) process: Option<String>,
    pub(crate) sockets: Vec<Socket>,
    pub(crate) icmp: Vec<ICMP>,
}

impl Communication {
    pub fn process(&self) -> [u8; TASK_COMM_LEN] {
        match self.process.as_ref() {
            Some(process) => super::string_to_u8_bytes((*process).clone()),
            None => [0; TASK_COMM_LEN],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Socket {
    pub(crate) protocol: IpProtocol,
    pub(crate) local_port: Option<u16>,
    pub(crate) remote_ip: Option<IpAddr>,
    pub(crate) remote_port: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ICMP {
    pub(crate) version: IcmpVersion,
    pub(crate) type_: u8,
    pub(crate) code: Option<u8>,
    pub(crate) remote_ip: Option<IpAddr>,
}
