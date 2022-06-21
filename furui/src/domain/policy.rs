use std::convert::TryInto;
use std::net::IpAddr;
use std::sync::Arc;

use aya_bpf::cty::c_char;
use aya_bpf::TASK_COMM_LEN;
use tokio::sync::Mutex;

use crate::domain::container::Container;
use crate::Containers;

#[derive(Debug, Clone)]
pub struct Policies {
    pub(crate) policies: Vec<Policy>,
}

impl Policies {
    pub async fn set_container_id(&mut self, containers: Arc<Mutex<Containers>>) {
        let ids = containers.lock().await.ids();

        for mut policy in &mut self.policies {
            if policy.container.name.len() == 0 {
                continue;
            }

            match ids.get(&policy.container.name) {
                Some(id) => {
                    policy.container.id = Some(id.to_string());
                }
                None => continue,
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct Policy {
    pub(crate) container: Container,
    pub(crate) communications: Vec<Communication>,
}

#[derive(Debug, Clone)]
pub struct Communication {
    pub(crate) process: Option<String>,
    pub(crate) sockets: Vec<Socket>,
    pub(crate) icmp: Vec<ICMP>,
}

impl Communication {
    pub fn process(&self) -> [c_char; TASK_COMM_LEN] {
        match self.process.as_ref().unwrap().as_bytes().try_into() {
            Ok(process) => process,
            Err(_) => [0; TASK_COMM_LEN],
        }
    }
}

#[derive(Debug, Clone)]
pub struct Socket {
    pub(crate) protocol: Protocol,
    pub(crate) local_port: Option<u16>,
    pub(crate) remote_ip: Option<IpAddr>,
    pub(crate) remote_port: Option<u16>,
}

impl Socket {
    pub fn protocol(&self) -> u8 {
        match self.protocol {
            Protocol::TCP => 6,
            Protocol::UDP => 11,
        }
    }
}

#[derive(Debug, Clone)]
pub enum Protocol {
    TCP,
    UDP,
}

#[derive(Debug, Clone)]
pub struct ICMP {
    pub(crate) version: u8,
    pub(crate) icmp_type: u8,
    pub(crate) code: Option<u8>,
    pub(crate) remote_ip: Option<IpAddr>,
}
