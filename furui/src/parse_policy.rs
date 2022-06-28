use std::fs::File;
use std::io::Read;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;

use dns_lookup::lookup_host;
use furui_common::IpProtocol;
use serde_derive::Deserialize;
use serde_yaml;
use tokio::sync::Mutex;
use tracing::warn;

use crate::domain::{self, Policies};

#[derive(Debug, Deserialize)]
pub struct ParsePolicies {
    #[serde(skip)]
    pub md5: String,
    pub policies: Vec<Policy>,
}

#[derive(Debug, Deserialize)]
pub struct Policy {
    pub container: Container,
    pub communications: Vec<Communication>,
}

#[derive(Debug, Deserialize)]
pub struct Container {
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub struct Communication {
    pub executable: Option<String>,
    #[serde(default)]
    pub sockets: Vec<Socket>,
    #[serde(default)]
    pub icmp: Vec<ICMP>,
}

#[derive(Debug, Deserialize)]
pub struct Socket {
    #[serde(default)]
    pub protocol: Protocol,
    pub local_port: Option<u16>,
    pub remote_host: Option<String>,
    pub remote_port: Option<u16>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all(deserialize = "lowercase"))]
pub enum Protocol {
    TCP,
    UDP,
    None,
}

impl Default for Protocol {
    fn default() -> Self {
        Protocol::None
    }
}

#[derive(Debug, Deserialize)]
pub struct ICMP {
    #[serde(default)]
    pub version: IcmpVersion,
    #[serde(rename = "type")]
    pub type_: u8,
    pub code: Option<u8>,
    pub remote_host: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all(deserialize = "lowercase"))]
pub enum IcmpVersion {
    V4,
    V6,
    None,
}

impl Default for IcmpVersion {
    fn default() -> Self {
        IcmpVersion::None
    }
}

impl ParsePolicies {
    pub fn new(path: PathBuf) -> anyhow::Result<ParsePolicies> {
        let mut f = File::open(path.as_path()).expect("file not found");
        let mut contents = String::new();

        f.read_to_string(&mut contents)?;

        let mut parsed_policies = serde_yaml::from_str::<ParsePolicies>(&contents)?;

        parsed_policies.md5 = format!("{:x}", md5::compute(contents));

        Ok(parsed_policies)
    }

    async fn lookup_host(
        containers: Arc<Mutex<domain::Containers>>,
        remote_host: &str,
    ) -> Vec<IpAddr> {
        match lookup_host(remote_host) {
            Ok(ips) => ips,
            Err(err) => match containers.lock().await.get_container_by_name(remote_host) {
                Some(container) => container.ip_addresses.unwrap(),
                None => {
                    warn!("failed to look up host: {} err: {}", remote_host, err);
                    vec![]
                }
            },
        }
    }

    pub async fn to_domain(
        &self,
        containers: Arc<Mutex<domain::Containers>>,
    ) -> anyhow::Result<Arc<Mutex<Policies>>> {
        let mut policies = Policies { policies: vec![] };

        for parsed_policy in &self.policies {
            let mut communications: Vec<domain::Communication> = vec![];
            for parsed_communication in &parsed_policy.communications {
                let mut communication = domain::Communication {
                    process: parsed_communication.executable.clone(),
                    sockets: vec![],
                    icmp: vec![],
                };

                // socket
                for parsed_socket in &parsed_communication.sockets {
                    let socket = domain::Socket {
                        protocol: match parsed_socket.protocol {
                            Protocol::TCP => IpProtocol::TCP,
                            Protocol::UDP => IpProtocol::UDP,
                            Protocol::None => IpProtocol::default(),
                        },
                        local_port: parsed_socket.local_port,
                        remote_ip: None,
                        remote_port: parsed_socket.remote_port,
                    };

                    match &parsed_socket.remote_host {
                        Some(remote_host) => {
                            for addr in
                                ParsePolicies::lookup_host(containers.clone(), remote_host).await
                            {
                                communication.sockets.push(domain::Socket {
                                    protocol: socket.protocol.clone(),
                                    local_port: socket.local_port,
                                    remote_ip: Some(addr),
                                    remote_port: socket.remote_port,
                                })
                            }
                        }
                        None => communication.sockets.push(socket),
                    }
                }

                // icmp
                for parsed_icmp in &parsed_communication.icmp {
                    let icmp_version = match parsed_icmp.version {
                        IcmpVersion::V4 => furui_common::IcmpVersion::V4,
                        IcmpVersion::V6 => furui_common::IcmpVersion::V6,
                        IcmpVersion::None => furui_common::IcmpVersion::default(),
                    };
                    let icmp = domain::ICMP {
                        version: icmp_version,
                        type_: parsed_icmp.type_,
                        code: parsed_icmp.code,
                        remote_ip: None,
                    };

                    match &parsed_icmp.remote_host {
                        Some(remote_host) => {
                            for addr in
                                ParsePolicies::lookup_host(containers.clone(), remote_host).await
                            {
                                communication.icmp.push(domain::ICMP {
                                    version: icmp_version,
                                    type_: parsed_icmp.type_,
                                    code: parsed_icmp.code,
                                    remote_ip: Some(addr),
                                })
                            }
                        }
                        None => communication.icmp.push(icmp),
                    }
                }

                communications.push(communication)
            }

            policies.policies.push(domain::Policy {
                container: domain::Container {
                    id: None,
                    ip_addresses: None,
                    name: parsed_policy.container.name.clone(),
                    pid: 0,
                },
                communications,
            })
        }

        policies.set_container_id(containers.clone()).await;

        Ok(Arc::new(Mutex::new(policies)))
    }
}
