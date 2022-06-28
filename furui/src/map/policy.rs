use std::convert::TryFrom;
use std::net::IpAddr;
use std::sync::Arc;

use anyhow::anyhow;
use aya::maps::{HashMap, MapRefMut};
use aya::Bpf;
use tokio::sync::Mutex;

use furui_common::{IcmpPolicyKey, IcmpPolicyValue, PolicyKey, PolicyValue};

use crate::domain;

pub struct PolicyMap {
    bpf: Arc<Mutex<Bpf>>,
}

impl PolicyMap {
    pub fn new(bpf: Arc<Mutex<Bpf>>) -> PolicyMap {
        PolicyMap { bpf }
    }

    pub async unsafe fn save(&self, policies: Arc<Mutex<domain::Policies>>) -> anyhow::Result<()> {
        let mut policy_list = HashMap::try_from(self.bpf.lock().await.map_mut("POLICY_LIST")?)?;
        let mut icmp_policy_list =
            HashMap::try_from(self.bpf.lock().await.map_mut("ICMP_POLICY_LIST")?)?;

        for policy in &policies.lock().await.policies {
            for communication in &policy.communications {
                let mut key: PolicyKey = std::mem::zeroed();

                key.container_id = policy.container.id();
                key.comm = communication.process();

                let mut value: PolicyValue = std::mem::zeroed();

                value.comm = communication.process();

                if communication.sockets.len() == 0
                    && communication.icmp.len() == 0
                    && communication.process.as_ref().unwrap().len() != 0
                {
                    policy_list.insert(key, value, 0)?;
                    continue;
                }

                for socket in &communication.sockets {
                    key.local_port = socket.local_port.unwrap_or(0);
                    key.remote_port = socket.remote_port.unwrap_or(0);
                    key.protocol = socket.protocol;

                    value.local_port = socket.remote_port.unwrap_or(0);
                    value.remote_port = socket.remote_port.unwrap_or(0);
                    value.protocol = socket.protocol;

                    match socket.remote_ip {
                        Some(IpAddr::V4(ip)) => {
                            key.remote_ip = ip.into();
                            value.remote_ip = ip.into();
                        }
                        Some(IpAddr::V6(ip)) => {
                            key.remote_ipv6 = ip.octets();
                            value.remote_ipv6 = ip.octets();
                        }
                        None => {}
                    }

                    policy_list.insert(key, value, 0)?;
                }

                for icmp in &communication.icmp {
                    let mut key: IcmpPolicyKey = std::mem::zeroed();

                    key.container_id = policy.container.id();
                    key.type_ = icmp.type_;
                    key.code = icmp.code.unwrap_or(0);

                    let mut value: IcmpPolicyValue = std::mem::zeroed();

                    value.type_ = icmp.type_;
                    value.code = icmp.code.unwrap_or(0);

                    if icmp.version.is_v4() || icmp.version.is_v6() {
                        key.version = icmp.version;
                        value.version = icmp.version;
                    } else {
                        return Err(anyhow!("Please specify icmp version in the policy"));
                    }

                    match icmp.remote_ip {
                        Some(IpAddr::V4(ip)) => {
                            key.remote_ip = ip.into();
                            value.remote_ip = ip.into();
                        }
                        Some(IpAddr::V6(ip)) => {
                            key.remote_ipv6 = ip.octets();
                            value.remote_ipv6 = ip.octets();
                        }
                        None => {}
                    }

                    icmp_policy_list.insert(key, value, 0)?;
                }
            }
        }

        Ok(())
    }

    pub async unsafe fn remove(
        &self,
        policies: Arc<Mutex<domain::Policies>>,
    ) -> anyhow::Result<()> {
        let mut policy_list: HashMap<MapRefMut, PolicyKey, PolicyValue> =
            HashMap::try_from(self.bpf.lock().await.map_mut("POLICY_LIST")?)?;
        let mut icmp_policy_list: HashMap<MapRefMut, IcmpPolicyKey, IcmpPolicyValue> =
            HashMap::try_from(self.bpf.lock().await.map_mut("ICMP_POLICY_LIST")?)?;

        for policy in &policies.lock().await.policies {
            for communication in &policy.communications {
                let mut key: PolicyKey = std::mem::zeroed();

                key.container_id = policy.container.id();
                key.comm = communication.process();

                if communication.sockets.len() == 0
                    && communication.icmp.len() == 0
                    && communication.process.as_ref().unwrap().len() != 0
                {
                    policy_list.remove(&key)?;
                    continue;
                }

                for socket in &communication.sockets {
                    key.local_port = socket.local_port.unwrap_or(0);
                    key.remote_port = socket.remote_port.unwrap_or(0);
                    key.protocol = socket.protocol;

                    match socket.remote_ip {
                        Some(IpAddr::V4(ip)) => {
                            key.remote_ip = ip.into();
                        }
                        Some(IpAddr::V6(ip)) => {
                            key.remote_ipv6 = ip.octets();
                        }
                        None => {}
                    }

                    policy_list.remove(&key)?;
                }

                for icmp in &communication.icmp {
                    let mut key: IcmpPolicyKey = std::mem::zeroed();

                    key.container_id = policy.container.id();
                    key.type_ = icmp.type_;
                    key.code = icmp.code.unwrap_or(0);

                    if icmp.version.is_v4() || icmp.version.is_v6() {
                        key.version = icmp.version;
                    } else {
                        return Err(anyhow!("Please specify icmp version in the policy"));
                    }

                    match icmp.remote_ip {
                        Some(IpAddr::V4(ip)) => {
                            key.remote_ip = ip.into();
                        }
                        Some(IpAddr::V6(ip)) => {
                            key.remote_ipv6 = ip.octets();
                        }
                        None => {}
                    }

                    icmp_policy_list.remove(&key)?;
                }
            }
        }

        Ok(())
    }
}
