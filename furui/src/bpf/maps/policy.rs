use std::{convert::TryFrom, net::IpAddr, sync::Arc};

use anyhow::anyhow;
use aya::{maps::HashMap, Ebpf};
use furui_common::{IcmpPolicyKey, IcmpPolicyValue, PolicyKey, PolicyValue};
use tokio::sync::{Mutex, RwLock};

use crate::domain;

/// The map entries a policy set expands into.
///
/// Producing this separately from writing it keeps the policy semantics --
/// which fields end up in the lookup key, and what an under-specified
/// communication means -- testable without a loaded eBPF program.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct PolicyEntries {
    pub sockets: Vec<(PolicyKey, PolicyValue)>,
    pub icmp: Vec<(IcmpPolicyKey, IcmpPolicyValue)>,
}

/// Expands `policies` into the entries the eBPF side looks up.
pub(crate) fn policy_entries(policies: &domain::Policies) -> anyhow::Result<PolicyEntries> {
    let mut entries = PolicyEntries::default();

    for policy in &policies.policies {
        let container_id = policy.container.id();

        for communication in &policy.communications {
            let comm = communication.process();

            // A communication that names an executable and nothing else allows
            // everything that process does, so it is stored as a bare
            // container+comm key.
            if communication.sockets.is_empty()
                && communication.icmp.is_empty()
                && communication
                    .process
                    .as_deref()
                    .is_some_and(|process| !process.is_empty())
            {
                entries.sockets.push((
                    PolicyKey {
                        container_id,
                        comm,
                        ..Default::default()
                    },
                    PolicyValue {
                        comm,
                        ..Default::default()
                    },
                ));
                continue;
            }

            for socket in &communication.sockets {
                let mut key = PolicyKey {
                    container_id,
                    comm,
                    local_port: socket.local_port.unwrap_or(0),
                    remote_port: socket.remote_port.unwrap_or(0),
                    protocol: socket.protocol,
                    ..Default::default()
                };
                let mut value = PolicyValue {
                    comm,
                    local_port: socket.local_port.unwrap_or(0),
                    remote_port: socket.remote_port.unwrap_or(0),
                    protocol: socket.protocol,
                    ..Default::default()
                };

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

                entries.sockets.push((key, value));
            }

            for icmp in &communication.icmp {
                if !icmp.version.is_v4() && !icmp.version.is_v6() {
                    return Err(anyhow!("Please specify icmp version in the policy"));
                }

                let mut key = IcmpPolicyKey {
                    container_id,
                    version: icmp.version,
                    type_: icmp.type_,
                    code: icmp.code.unwrap_or(0),
                    ..Default::default()
                };
                let mut value = IcmpPolicyValue {
                    version: icmp.version,
                    type_: icmp.type_,
                    code: icmp.code.unwrap_or(0),
                    ..Default::default()
                };

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

                entries.icmp.push((key, value));
            }
        }
    }

    Ok(entries)
}

pub struct PolicyMap {
    bpf: Arc<Mutex<Ebpf>>,
}

impl PolicyMap {
    pub fn new(bpf: Arc<Mutex<Ebpf>>) -> PolicyMap {
        PolicyMap { bpf }
    }

    pub async fn save(&self, policies: Arc<RwLock<domain::Policies>>) -> anyhow::Result<()> {
        let entries = policy_entries(&*policies.read().await)?;

        let mut bpf = self.bpf.lock().await;

        let mut policy_list: HashMap<_, PolicyKey, PolicyValue> =
            HashMap::try_from(bpf.map_mut("POLICY_LIST").unwrap())?;
        for (key, value) in entries.sockets {
            policy_list.insert(key, value, 0)?;
        }

        let mut icmp_policy_list: HashMap<_, IcmpPolicyKey, IcmpPolicyValue> =
            HashMap::try_from(bpf.map_mut("ICMP_POLICY_LIST").unwrap())?;
        for (key, value) in entries.icmp {
            icmp_policy_list.insert(key, value, 0)?;
        }

        Ok(())
    }

    pub async fn remove(&self) -> anyhow::Result<()> {
        let mut bpf = self.bpf.lock().await;

        let mut policy_list: HashMap<_, PolicyKey, PolicyValue> =
            HashMap::try_from(bpf.map_mut("POLICY_LIST").unwrap())?;
        for key in policy_list.keys().collect::<Result<Vec<_>, _>>()? {
            policy_list.remove(&key)?;
        }

        let mut icmp_policy_list: HashMap<_, IcmpPolicyKey, IcmpPolicyValue> =
            HashMap::try_from(bpf.map_mut("ICMP_POLICY_LIST").unwrap())?;
        for key in icmp_policy_list.keys().collect::<Result<Vec<_>, _>>()? {
            icmp_policy_list.remove(&key)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use furui_common::{IcmpVersion, IpProtocol, CONTAINER_ID_LEN, TASK_COMM_LEN};

    use super::*;
    use crate::domain::{Communication, Container, Policies, Policy, Socket, ICMP};

    fn container(id: &str) -> Container {
        Container {
            id: Some(id.to_string()),
            ip_addresses: None,
            name: format!("/{id}"),
            pid: 0,
        }
    }

    fn policies(communications: Vec<Communication>) -> Policies {
        Policies {
            policies: vec![Policy {
                container: container("abcdef123456"),
                communications,
            }],
        }
    }

    fn comm(process: Option<&str>, sockets: Vec<Socket>, icmp: Vec<ICMP>) -> Communication {
        Communication {
            process: process.map(str::to_string),
            sockets,
            icmp,
        }
    }

    fn c_id(id: &str) -> [aya_ebpf::cty::c_char; CONTAINER_ID_LEN] {
        let mut out = [0; CONTAINER_ID_LEN];
        for (slot, byte) in out.iter_mut().zip(id.bytes()) {
            *slot = byte as aya_ebpf::cty::c_char;
        }
        out
    }

    fn comm_bytes(name: &str) -> [u8; TASK_COMM_LEN] {
        let mut out = [0; TASK_COMM_LEN];
        out[..name.len()].copy_from_slice(name.as_bytes());
        out
    }

    #[test]
    fn socket_fields_land_in_the_key() {
        let entries = policy_entries(&policies(vec![comm(
            Some("nginx"),
            vec![Socket {
                protocol: IpProtocol::TCP,
                local_port: Some(80),
                remote_ip: Some("10.0.0.1".parse().unwrap()),
                remote_port: Some(443),
            }],
            vec![],
        )]))
        .unwrap();

        assert_eq!(entries.icmp, vec![]);
        let (key, value) = entries.sockets[0];

        assert_eq!(key.container_id, c_id("abcdef123456"));
        assert_eq!(key.comm, comm_bytes("nginx"));
        assert_eq!(key.local_port, 80);
        assert_eq!(key.remote_port, 443);
        assert_eq!(key.protocol, IpProtocol::TCP);
        assert_eq!(
            key.remote_ip,
            u32::from(std::net::Ipv4Addr::new(10, 0, 0, 1))
        );
        assert_eq!(key.remote_ipv6, [0; 16]);

        // The value mirrors the key's ports; it used to copy `remote_port` into
        // `local_port`.
        assert_eq!(value.local_port, 80);
        assert_eq!(value.remote_port, 443);
    }

    #[test]
    fn an_ipv6_remote_goes_in_the_v6_field_only() {
        let entries = policy_entries(&policies(vec![comm(
            Some("nginx"),
            vec![Socket {
                protocol: IpProtocol::TCP,
                local_port: None,
                remote_ip: Some("2001:db8::1".parse().unwrap()),
                remote_port: None,
            }],
            vec![],
        )]))
        .unwrap();

        let (key, _) = entries.sockets[0];
        assert_eq!(key.remote_ip, 0);
        assert_eq!(
            key.remote_ipv6,
            "2001:db8::1"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets()
        );
        // Unset ports are wildcards, stored as zero.
        assert_eq!(key.local_port, 0);
        assert_eq!(key.remote_port, 0);
    }

    #[test]
    fn an_executable_with_no_rules_allows_everything_it_does() {
        let entries = policy_entries(&policies(vec![comm(Some("nginx"), vec![], vec![])])).unwrap();

        assert_eq!(entries.sockets.len(), 1);
        let (key, _) = entries.sockets[0];
        assert_eq!(key.comm, comm_bytes("nginx"));
        assert_eq!(key.protocol, IpProtocol::default());
        assert_eq!(key.local_port, 0);
        assert_eq!(key.remote_port, 0);
    }

    #[test]
    fn a_communication_with_nothing_in_it_produces_nothing() {
        // Used to panic: the "executable only" branch unwrapped `process`.
        let entries = policy_entries(&policies(vec![comm(None, vec![], vec![])])).unwrap();

        assert_eq!(entries, PolicyEntries::default());
    }

    #[test]
    fn each_socket_becomes_its_own_entry() {
        let entries = policy_entries(&policies(vec![comm(
            Some("nginx"),
            vec![
                Socket {
                    protocol: IpProtocol::TCP,
                    local_port: Some(80),
                    remote_ip: None,
                    remote_port: None,
                },
                Socket {
                    protocol: IpProtocol::TCP,
                    local_port: Some(443),
                    remote_ip: None,
                    remote_port: None,
                },
            ],
            vec![],
        )]))
        .unwrap();

        assert_eq!(entries.sockets.len(), 2);
        assert_eq!(entries.sockets[0].0.local_port, 80);
        assert_eq!(entries.sockets[1].0.local_port, 443);
    }

    #[test]
    fn icmp_entries_carry_type_code_and_version() {
        let entries = policy_entries(&policies(vec![comm(
            Some("ping"),
            vec![],
            vec![ICMP {
                version: IcmpVersion::V4,
                type_: 8,
                code: Some(0),
                remote_ip: Some("10.0.0.2".parse().unwrap()),
            }],
        )]))
        .unwrap();

        assert_eq!(entries.sockets, vec![]);
        let (key, value) = entries.icmp[0];
        assert_eq!(key.container_id, c_id("abcdef123456"));
        assert_eq!(key.version, IcmpVersion::V4);
        assert_eq!(key.type_, 8);
        assert_eq!(key.code, 0);
        assert_eq!(
            key.remote_ip,
            u32::from(std::net::Ipv4Addr::new(10, 0, 0, 2))
        );
        assert_eq!(value.type_, 8);
    }

    #[test]
    fn icmp_without_a_version_is_rejected() {
        let err = policy_entries(&policies(vec![comm(
            Some("ping"),
            vec![],
            vec![ICMP {
                version: IcmpVersion::Default,
                type_: 8,
                code: None,
                remote_ip: None,
            }],
        )]))
        .unwrap_err();

        assert!(err.to_string().contains("icmp version"));
    }

    #[test]
    fn an_unresolved_container_gets_a_zero_id() {
        // `Policies::set_container_id` clears the id when the container is not
        // running, and the entry still has to be well-formed.
        let mut policies = policies(vec![comm(Some("nginx"), vec![], vec![])]);
        policies.policies[0].container.id = None;

        let entries = policy_entries(&policies).unwrap();
        assert_eq!(entries.sockets[0].0.container_id, [0; CONTAINER_ID_LEN]);
    }
}
