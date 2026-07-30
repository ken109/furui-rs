use std::{convert::TryFrom, net::IpAddr};

use anyhow::{anyhow, Context as _};
use futures::{stream::BoxStream, StreamExt};
use hyper_util::rt::TokioIo;
use tokio::net::UnixStream;
use tonic::transport::{Channel, Endpoint};
use tower::service_fn;
use tracing::warn;

use crate::{
    domain::Container,
    runtime::{
        k8s_cri::{
            runtime_service_client::RuntimeServiceClient, ContainerFilter, ContainerState,
            ContainerStateValue, ContainerStatusRequest, ExecSyncRequest, GetEventsRequest,
            ListContainersRequest,
        },
        ContainerAction, ContainerEvent,
    },
};

const CONTAINERD_SOCKET: &str = "/run/containerd/containerd.sock";

pub(super) struct RuntimeKubernetesCri {
    cri: RuntimeServiceClient<Channel>,
}

impl RuntimeKubernetesCri {
    pub(super) async fn new() -> anyhow::Result<RuntimeKubernetesCri> {
        // The URI is ignored -- the connector below dials the unix socket --
        // but tonic still requires a well-formed one.
        let channel = Endpoint::try_from("http://[::]")
            .context("failed to build the CRI endpoint")?
            .connect_with_connector(service_fn(move |_| async move {
                let io = TokioIo::new(UnixStream::connect(CONTAINERD_SOCKET).await?);
                Ok::<_, std::io::Error>(io)
            }))
            .await
            .with_context(|| format!("failed to connect to CRI at {CONTAINERD_SOCKET}"))?;

        Ok(RuntimeKubernetesCri {
            cri: RuntimeServiceClient::new(channel),
        })
    }

    pub(super) async fn container_ids(&self) -> anyhow::Result<Vec<String>> {
        let request = tonic::Request::new(ListContainersRequest {
            filter: Some(ContainerFilter {
                state: Some(ContainerStateValue {
                    state: ContainerState::ContainerRunning as i32,
                }),
                ..Default::default()
            }),
        });
        let response = self.cri.clone().list_containers(request).await?;

        Ok(response
            .get_ref()
            .containers
            .iter()
            .map(|c| c.id.clone())
            .collect())
    }

    pub(super) async fn set_container_inspect(
        &self,
        container: &mut Container,
    ) -> anyhow::Result<()> {
        let id = container.id.clone();

        let request = tonic::Request::new(ContainerStatusRequest {
            container_id: id.clone(),
            verbose: true,
        });
        let inspect = self.cri.clone().container_status(request).await?;

        // Everything the CRI returns here is optional in the protocol. A
        // container missing any of it is one furui cannot police, so name what
        // was missing instead of panicking inside the event loop.
        let metadata = inspect
            .get_ref()
            .status
            .clone()
            .and_then(|status| status.metadata)
            .ok_or_else(|| anyhow!("CRI returned no metadata for container {id}"))?;

        let raw_info = inspect
            .get_ref()
            .info
            .get("info")
            .ok_or_else(|| anyhow!("CRI returned no verbose info for container {id}"))?;

        // `info` is JSON, whatever the surrounding protocol is.
        let info: serde_json::Value = serde_json::from_str(raw_info)
            .with_context(|| format!("CRI returned unparseable info for container {id}"))?;

        let pid = info["pid"]
            .as_u64()
            .ok_or_else(|| anyhow!("CRI reported no pid for container {id}"))?;

        let mut addrs = self.ipv4_addresses(&id).await?;
        addrs.extend(self.ipv6_addresses(&id).await?);

        container.ip_addresses = addrs;
        container.name = metadata.name;
        container.pid = pid as u32;

        Ok(())
    }

    /// Runs a command in the container and returns its stdout.
    async fn exec(&self, container_id: &str, cmd: &[&str]) -> anyhow::Result<String> {
        let request = tonic::Request::new(ExecSyncRequest {
            container_id: container_id.to_string(),
            cmd: cmd.iter().map(|arg| arg.to_string()).collect(),
            timeout: 0,
        });

        let response = self
            .cri
            .clone()
            .exec_sync(request)
            .await
            .with_context(|| format!("failed to run {cmd:?} in container {container_id}"))?;

        Ok(String::from_utf8_lossy(&response.get_ref().stdout).into_owned())
    }

    async fn ipv4_addresses(&self, container_id: &str) -> anyhow::Result<Vec<IpAddr>> {
        let fib_trie = self
            .exec(container_id, &["cat", "/proc/net/fib_trie"])
            .await?;

        Ok(parse_fib_trie(&fib_trie))
    }

    async fn ipv6_addresses(&self, container_id: &str) -> anyhow::Result<Vec<IpAddr>> {
        let if_inet6 = self
            .exec(container_id, &["cat", "/proc/net/if_inet6"])
            .await?;

        Ok(parse_if_inet6(&if_inet6))
    }

    pub(super) async fn container_events(&self) -> BoxStream<'_, ContainerEvent> {
        let request = tonic::Request::new(GetEventsRequest {});

        let events = match self.cri.clone().get_container_events(request).await {
            Ok(response) => response.into_inner(),
            Err(err) => {
                warn!("failed to subscribe to CRI container events: {err}");
                return Box::pin(futures::stream::empty());
            }
        };

        // A malformed event is dropped rather than taken as a reason to tear
        // the watcher down.
        Box::pin(events.filter_map(|event| async move {
            let event = match event {
                Ok(event) => event,
                Err(err) => {
                    warn!("failed to read a CRI container event: {err}");
                    return None;
                }
            };

            Some(ContainerEvent {
                id: event.container_id,
                action: match event.container_event_type {
                    1 => ContainerAction::Unpause,
                    2 => ContainerAction::Pause,
                    3 => ContainerAction::Die,
                    _ => ContainerAction::Unknown,
                },
            })
        }))
    }
}

/// The container's own IPv4 addresses, from `/proc/net/fib_trie`.
///
/// The table indents an address on one line and its scope on the next, so a
/// `/32 host` line means the address *above* it is local:
///
/// ```text
///     |-- 172.17.0.2
///        /32 host LOCAL
/// ```
fn parse_fib_trie(fib_trie: &str) -> Vec<IpAddr> {
    let mut addresses: Vec<IpAddr> = vec![];
    let mut previous = "";

    for line in fib_trie.lines() {
        if line.contains("32 host") {
            if let Some(Ok(address)) = previous
                .split_whitespace()
                .next_back()
                .map(str::parse::<IpAddr>)
            {
                if !address.is_loopback() && !addresses.contains(&address) {
                    addresses.push(address);
                }
            }
        }
        previous = line;
    }

    addresses
}

/// The container's own IPv6 addresses, from `/proc/net/if_inet6`.
///
/// Each row starts with the address as 32 hex digits and ends with the
/// interface name:
///
/// ```text
/// 00000000000000000000000000000001 01 80 10 80       lo
/// fe80000000000000004281fffe4d1234 02 40 20 80     eth0
/// ```
fn parse_if_inet6(if_inet6: &str) -> Vec<IpAddr> {
    let mut addresses: Vec<IpAddr> = vec![];

    for line in if_inet6.lines() {
        let Some(interface) = line.split_whitespace().next_back() else {
            continue;
        };
        if interface == "lo" {
            continue;
        }

        // Slicing a short or non-ASCII line by byte index would panic.
        let Some(hex) = line.get(..32) else {
            continue;
        };
        if !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            continue;
        }

        let grouped = hex
            .as_bytes()
            .chunks(4)
            .map(|group| std::str::from_utf8(group).unwrap_or_default())
            .collect::<Vec<_>>()
            .join(":");

        if let Ok(address) = grouped.parse::<IpAddr>() {
            if !addresses.contains(&address) {
                addresses.push(address);
            }
        }
    }

    addresses
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    const FIB_TRIE: &str = "\
Main:
  +-- 0.0.0.0/0 3 0 5
     |-- 0.0.0.0
        /0 universe UNICAST
     +-- 172.17.0.0/16 2 0 2
        |-- 172.17.0.0
           /32 link BROADCAST
           /16 link UNICAST
        |-- 172.17.0.2
           /32 host LOCAL
Local:
  +-- 127.0.0.0/8 2 0 2
     |-- 127.0.0.1
        /32 host LOCAL
";

    #[test]
    fn reads_the_container_address_above_the_host_line() {
        assert_eq!(
            parse_fib_trie(FIB_TRIE),
            vec![IpAddr::V4(Ipv4Addr::new(172, 17, 0, 2))]
        );
    }

    #[test]
    fn a_truncated_or_empty_fib_trie_yields_nothing() {
        let none: Vec<IpAddr> = vec![];
        // `reduce(...).unwrap()` used to panic on an empty table, and
        // `.last().unwrap()` on a `/32 host` line with nothing above it.
        assert_eq!(parse_fib_trie(""), none);
        assert_eq!(parse_fib_trie("/32 host LOCAL"), none);
        assert_eq!(parse_fib_trie("Main:\n  not an address\n /32 host"), none);
    }

    const IF_INET6: &str = "\
00000000000000000000000000000001 01 80 10 80       lo
fe80000000000000004281fffe4d1234 02 40 20 80     eth0
20010db8000000000000000000000001 02 40 00 80     eth0
";

    #[test]
    fn reads_every_address_except_loopback() {
        assert_eq!(
            parse_if_inet6(IF_INET6),
            vec![
                // fe80 0000 0000 0000 0042 81ff fe4d 1234
                IpAddr::V6("fe80::42:81ff:fe4d:1234".parse::<Ipv6Addr>().unwrap()),
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            ]
        );
    }

    #[test]
    fn a_short_or_malformed_row_is_skipped() {
        let none: Vec<IpAddr> = vec![];
        // The address was sliced as `&line[0..4]`, `&line[4..8]` and so on,
        // which panics on anything shorter than 32 bytes.
        assert_eq!(parse_if_inet6(""), none);
        assert_eq!(parse_if_inet6("deadbeef eth0"), none);
        assert_eq!(
            parse_if_inet6("zzzz0000000000000000000000000001 02 40 00 80 eth0"),
            none
        );
        assert_eq!(
            parse_if_inet6("\u{3042}\u{3044}\u{3046} 02 40 00 80 eth0"),
            none
        );
    }
}
