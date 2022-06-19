use std::convert::TryFrom;
use std::mem::MaybeUninit;
use std::net::IpAddr;
use std::sync::Arc;

use anyhow::anyhow;
use aya::maps::HashMap;
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
                let mut key_uninit = MaybeUninit::<PolicyKey>::zeroed();
                let mut key_ptr = key_uninit.as_mut_ptr();
                (*key_ptr).container_id = policy.container.id();
                (*key_ptr).comm = communication.process();

                let mut value_uninit = MaybeUninit::<PolicyValue>::zeroed();
                let mut value_ptr = value_uninit.as_mut_ptr();
                (*value_ptr).comm = communication.process();

                if communication.sockets.len() == 0
                    && communication.icmp.len() == 0
                    && communication.process.as_ref().unwrap().len() != 0
                {
                    policy_list.insert(key_uninit.assume_init(), value_uninit.assume_init(), 0)?;
                    continue;
                }

                for socket in &communication.sockets {
                    (*key_ptr).local_port = socket.local_port.unwrap();
                    (*key_ptr).remote_port = socket.remote_port.unwrap();
                    (*key_ptr).protocol = socket.protocol();

                    (*value_ptr).local_port = socket.remote_port.unwrap();
                    (*value_ptr).remote_port = socket.remote_port.unwrap();
                    (*value_ptr).protocol = socket.protocol();

                    match socket.remote_ip.unwrap() {
                        IpAddr::V4(ip) => {
                            (*key_ptr).remote_ip = ip.into();
                            (*value_ptr).remote_ip = ip.into();
                        }
                        IpAddr::V6(ip) => {
                            (*key_ptr).remote_ipv6 = ip.octets();
                            (*value_ptr).remote_ipv6 = ip.octets();
                        }
                    }

                    policy_list.insert(key_uninit.assume_init(), value_uninit.assume_init(), 0)?;
                }

                for icmp in &communication.icmp {
                    let mut key_uninit = MaybeUninit::<IcmpPolicyKey>::zeroed();
                    let mut key_ptr = key_uninit.as_mut_ptr();
                    (*key_ptr).container_id = policy.container.id();
                    (*key_ptr).icmp_type = icmp.icmp_type;
                    (*key_ptr).code = icmp.code.unwrap();

                    let mut value_uninit = MaybeUninit::<IcmpPolicyValue>::zeroed();
                    let mut value_ptr = value_uninit.as_mut_ptr();
                    (*value_ptr).icmp_type = icmp.icmp_type;
                    (*value_ptr).code = icmp.code.unwrap();

                    if icmp.version == 4 || icmp.version == 6 {
                        (*key_ptr).version = icmp.version;
                        (*value_ptr).version = icmp.version;
                    } else {
                        return Err(anyhow!("Please specify icmp version in the policy"));
                    }

                    match icmp.remote_ip.unwrap() {
                        IpAddr::V4(ip) => {
                            (*key_ptr).remote_ip = ip.into();
                            (*value_ptr).remote_ip = ip.into();
                        }
                        IpAddr::V6(ip) => {
                            (*key_ptr).remote_ipv6 = ip.octets();
                            (*value_ptr).remote_ipv6 = ip.octets();
                        }
                    }

                    icmp_policy_list.insert(
                        key_uninit.assume_init(),
                        value_uninit.assume_init(),
                        0,
                    )?;
                }
            }
        }

        Ok(())
    }
}
