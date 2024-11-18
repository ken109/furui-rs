use std::{net::IpAddr, sync::Arc};

use furui_common::{IcmpVersion, IpProtocol, TASK_COMM_LEN};
use tokio::sync::Mutex;

use crate::{domain::container::Container, Containers};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Policies {
    pub(crate) policies: Vec<Policy>,
}

impl Policies {
    pub async fn set_container_id(&mut self, containers: Arc<Mutex<Containers>>) {
        let ids = containers.lock().await.ids();

        for policy in &mut self.policies {
            if policy.container.name.len() == 0 {
                continue;
            }

            match ids.get(&policy.container.name) {
                Some(id) => {
                    policy.container.id = Some(id.to_string());
                }
                None => {
                    policy.container.id = None;
                }
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    pub(crate) container: Container,
    pub(crate) communications: Vec<Communication>,
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
