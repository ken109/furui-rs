//! Reading a policy file and turning it into domain policies.

use std::{
    collections::{BTreeSet, HashMap},
    fs::File,
    io::Read,
    net::IpAddr,
    path::PathBuf,
    sync::Arc,
};

use dns_lookup::lookup_host;
use furui_common::IpProtocol;
use tokio::sync::RwLock;
use tracing::warn;

use crate::{
    domain::{self, Policies},
    policy::yaml::{IcmpVersion, ParsePolicies, Protocol},
};

impl ParsePolicies {
    pub fn new(path: PathBuf) -> anyhow::Result<ParsePolicies> {
        let mut f = File::open(path.as_path()).expect("file not found");
        let mut contents = String::new();

        f.read_to_string(&mut contents)?;

        let config = serde_yaml::from_str::<ParsePolicies>(&contents)?;

        Ok(config)
    }

    /// Every `remote_host` the document mentions, deduplicated.
    fn remote_hosts(&self) -> BTreeSet<&str> {
        self.policies
            .iter()
            .flat_map(|policy| &policy.communications)
            .flat_map(|communication| {
                let sockets = communication
                    .sockets
                    .iter()
                    .filter_map(|socket| socket.remote_host.as_deref());
                let icmp = communication
                    .icmp
                    .iter()
                    .filter_map(|icmp| icmp.remote_host.as_deref());
                sockets.chain(icmp)
            })
            .collect()
    }

    /// Resolves a `remote_host` to addresses, by DNS or by container name.
    async fn lookup_host(
        containers: Arc<RwLock<domain::Containers>>,
        remote_host: &str,
    ) -> Vec<IpAddr> {
        match lookup_host(remote_host) {
            Ok(ips) => ips.collect(),
            Err(err) => match containers.read().await.get_container_by_name(remote_host) {
                Some(container) => container.ip_addresses,
                None => {
                    warn!("failed to look up host: {} err: {}", remote_host, err);
                    vec![]
                }
            },
        }
    }

    pub async fn to_policies(
        &self,
        containers: Arc<RwLock<domain::Containers>>,
    ) -> anyhow::Result<Arc<RwLock<Policies>>> {
        // Resolve first so that the conversion itself stays pure. Each host is
        // looked up once, however many rules mention it.
        let mut resolved = HashMap::new();
        for host in self.remote_hosts() {
            let addrs = Self::lookup_host(containers.clone(), host).await;
            resolved.insert(host.to_string(), addrs);
        }

        let mut policies = self.build(&resolved);
        policies.set_container_id(containers.clone()).await;

        Ok(Arc::new(RwLock::new(policies)))
    }

    /// Converts the parsed document into domain policies.
    ///
    /// `resolved` supplies the addresses for each `remote_host`; a rule naming
    /// a host that resolved to nothing expands to no rules at all, which is
    /// what makes an unresolvable host fail closed.
    fn build(&self, resolved: &HashMap<String, Vec<IpAddr>>) -> Policies {
        let addrs = |host: &Option<String>| -> Option<&[IpAddr]> {
            host.as_ref()
                .map(|host| resolved.get(host).map_or(&[][..], Vec::as_slice))
        };

        let policies = self
            .policies
            .iter()
            .map(|parsed_policy| {
                let communications = parsed_policy
                    .communications
                    .iter()
                    .map(|parsed_communication| {
                        let mut sockets = vec![];
                        for parsed_socket in &parsed_communication.sockets {
                            let protocol = match parsed_socket.protocol {
                                Protocol::TCP => IpProtocol::TCP,
                                Protocol::UDP => IpProtocol::UDP,
                                Protocol::None => IpProtocol::default(),
                            };
                            let socket = |remote_ip| domain::Socket {
                                protocol,
                                local_port: parsed_socket.local_port,
                                remote_ip,
                                remote_port: parsed_socket.remote_port,
                            };

                            match addrs(&parsed_socket.remote_host) {
                                Some(addrs) => {
                                    sockets.extend(addrs.iter().map(|addr| socket(Some(*addr))))
                                }
                                None => sockets.push(socket(None)),
                            }
                        }

                        let mut icmp = vec![];
                        for parsed_icmp in &parsed_communication.icmp {
                            let version = match parsed_icmp.version {
                                IcmpVersion::V4 => furui_common::IcmpVersion::V4,
                                IcmpVersion::V6 => furui_common::IcmpVersion::V6,
                                IcmpVersion::None => furui_common::IcmpVersion::default(),
                            };
                            let rule = |remote_ip| domain::ICMP {
                                version,
                                type_: parsed_icmp.type_,
                                code: parsed_icmp.code,
                                remote_ip,
                            };

                            match addrs(&parsed_icmp.remote_host) {
                                Some(addrs) => {
                                    icmp.extend(addrs.iter().map(|addr| rule(Some(*addr))))
                                }
                                None => icmp.push(rule(None)),
                            }
                        }

                        domain::Communication {
                            process: parsed_communication.executable.clone(),
                            sockets,
                            icmp,
                        }
                    })
                    .collect();

                domain::Policy {
                    container: domain::PolicyTarget::new(parsed_policy.container.name.clone()),
                    communications,
                }
            })
            .collect();

        Policies { policies }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    fn examples() -> Vec<PathBuf> {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("example");
        let mut found = vec![];
        let mut stack = vec![dir];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).unwrap().flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.extension().is_some_and(|ext| ext == "yaml") {
                    found.push(path);
                }
            }
        }
        found.sort();
        found
    }

    /// Every policy shipped in `example/` has to parse, or the documentation
    /// tells people to write something furui rejects.
    #[test]
    fn the_shipped_examples_parse() {
        let mut failures = vec![];
        for path in examples() {
            if let Err(err) = ParsePolicies::new(path.clone()) {
                failures.push(format!("{}: {err}", path.display()));
            }
        }
        assert!(failures.is_empty(), "{failures:#?}");
    }

    /// Every policy document in the README has to parse, or the documentation
    /// is telling people to write something furui rejects.
    #[test]
    fn the_documented_examples_parse() {
        let readme = std::fs::read_to_string(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .unwrap()
                .join("README.md"),
        )
        .unwrap();

        let mut blocks = 0;
        let mut inside = false;
        let mut current = String::new();

        for line in readme.lines() {
            if inside && line.trim_start().starts_with("```") {
                inside = false;
                if current.starts_with("policies:") {
                    blocks += 1;
                    serde_yaml::from_str::<ParsePolicies>(&current)
                        .unwrap_or_else(|err| panic!("README block {blocks}: {err}\n{current}"));
                }
                current.clear();
            } else if inside {
                current.push_str(line);
                current.push('\n');
            } else if line.trim_start() == "```yaml" {
                inside = true;
            }
        }

        assert!(
            blocks >= 2,
            "expected policy examples in the README, found {blocks}"
        );
    }

    fn parse(yaml: &str) -> ParsePolicies {
        serde_yaml::from_str(yaml).unwrap()
    }

    const WITH_HOSTS: &str = r#"
policies:
  - container:
      name: "web"
    communications:
      - executable: "nginx"
        sockets:
          - protocol: "tcp"
            remote_host: "db"
            remote_port: 3306
        icmp:
          - version: "v4"
            type: 8
            remote_host: "db"
"#;

    #[test]
    fn each_resolved_address_becomes_its_own_rule() {
        let parsed = parse(WITH_HOSTS);
        let resolved = HashMap::from([(
            "db".to_string(),
            vec![
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                IpAddr::V6(Ipv6Addr::LOCALHOST),
            ],
        )]);

        let policies = parsed.build(&resolved);
        let communication = &policies.policies[0].communications[0];

        assert_eq!(communication.sockets.len(), 2);
        assert_eq!(
            communication.sockets[0].remote_ip,
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
        );
        assert_eq!(
            communication.sockets[1].remote_ip,
            Some(IpAddr::V6(Ipv6Addr::LOCALHOST))
        );
        // Fields other than the address are copied to each expansion.
        assert!(communication
            .sockets
            .iter()
            .all(|s| s.remote_port == Some(3306) && s.protocol == IpProtocol::TCP));

        assert_eq!(communication.icmp.len(), 2);
    }

    #[test]
    fn a_host_that_resolves_to_nothing_produces_no_rules() {
        let parsed = parse(WITH_HOSTS);

        let policies = parsed.build(&HashMap::new());
        let communication = &policies.policies[0].communications[0];

        // Fail closed: a rule naming an unreachable host must not turn into a
        // wildcard rule that allows every address.
        assert_eq!(communication.sockets, vec![]);
        assert_eq!(communication.icmp, vec![]);
    }

    #[test]
    fn a_rule_without_a_host_stays_a_wildcard() {
        let parsed = parse(
            r#"
policies:
  - container:
      name: "web"
    communications:
      - executable: "nginx"
        sockets:
          - protocol: "tcp"
            local_port: 80
"#,
        );

        let communication = &parsed.build(&HashMap::new()).policies[0].communications[0];
        assert_eq!(communication.sockets.len(), 1);
        assert_eq!(communication.sockets[0].remote_ip, None);
        assert_eq!(communication.sockets[0].local_port, Some(80));
    }

    #[test]
    fn an_omitted_protocol_falls_back_to_the_default() {
        let parsed = parse(
            r#"
policies:
  - container:
      name: "web"
    communications:
      - executable: "nginx"
        sockets:
          - local_port: 80
"#,
        );

        let communication = &parsed.build(&HashMap::new()).policies[0].communications[0];
        assert_eq!(communication.sockets[0].protocol, IpProtocol::default());
    }

    #[test]
    fn every_host_is_collected_once() {
        let parsed = parse(WITH_HOSTS);
        assert_eq!(parsed.remote_hosts(), BTreeSet::from(["db"]));
    }

    #[test]
    fn the_container_id_starts_unresolved() {
        let parsed = parse(WITH_HOSTS);
        let policies = parsed.build(&HashMap::new());

        assert_eq!(policies.policies[0].container.name, "web");
        assert_eq!(policies.policies[0].container.id, None);
    }
}
