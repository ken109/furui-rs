use std::{convert::TryFrom, net::IpAddr};

use futures::{stream::BoxStream, StreamExt};
use hyper_util::rt::TokioIo;
use serde_yaml::Value;
use tokio::net::UnixStream;
use tonic::transport::{Channel, Endpoint};
use tower::service_fn;

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

pub(super) struct RuntimeKubernetesCri {
    cri: RuntimeServiceClient<Channel>,
}

impl RuntimeKubernetesCri {
    pub(super) async fn new() -> anyhow::Result<RuntimeKubernetesCri> {
        let path = "/run/containerd/containerd.sock";
        let channel = Endpoint::try_from("http://[::]")
            .unwrap()
            .connect_with_connector(service_fn(move |_| {
                async move {
                    // Connect to a Uds socket
                    let io = TokioIo::new(UnixStream::connect(path).await?);
                    Ok::<_, std::io::Error>(io)
                }
            }))
            .await
            .expect("Could not create client.");

        let client = RuntimeServiceClient::new(channel);
        Ok(RuntimeKubernetesCri { cri: client })
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
        let containers = &response.get_ref().containers;

        Ok(containers.iter().map(|c| c.id.clone()).collect())
    }

    pub(super) async fn set_container_inspect(
        &self,
        container: &mut Container,
    ) -> anyhow::Result<()> {
        let container_id = container.id.clone().unwrap();
        let request = tonic::Request::new(ContainerStatusRequest {
            container_id: container_id.to_string(),
            verbose: true,
        });
        let inspect = self.cri.clone().container_status(request).await?;

        let metadata = inspect.get_ref().status.clone().unwrap().metadata.unwrap();
        let raw_info = &inspect.get_ref().info.get("info").unwrap();

        let info: Value = serde_json::from_str(raw_info).unwrap();

        let mut addrs: Vec<IpAddr> = vec![];
        addrs.extend(self.get_ipv4_addresses(container_id.clone()).await?);
        addrs.extend(self.get_ipv6_addresses(container_id).await?);

        container.ip_addresses = Some(addrs);
        container.name = metadata.name;
        container.pid = info["pid"].as_u64().unwrap() as u32;

        Ok(())
    }

    async fn get_ipv4_addresses(&self, container_id: String) -> anyhow::Result<Vec<IpAddr>> {
        let request = tonic::Request::new(ExecSyncRequest {
            container_id,
            cmd: vec!["cat".to_string(), "/proc/net/fib_trie".to_string()],
            timeout: 0,
        });

        let response = self.cri.clone().exec_sync(request).await.unwrap();

        let result = String::from_utf8(response.get_ref().stdout.clone()).unwrap();

        let mut ip_addresses: Vec<IpAddr> = vec![];

        result
            .lines()
            .reduce(|a, b| {
                if b.contains("32 host") {
                    let ip_str = a.split_whitespace().last().unwrap();
                    let ip_address = ip_str.parse::<IpAddr>().unwrap();
                    if ip_str != "127.0.0.1" && !ip_addresses.contains(&ip_address) {
                        ip_addresses.push(ip_address);
                    }
                }
                b
            })
            .unwrap();

        Ok(ip_addresses)
    }

    async fn get_ipv6_addresses(&self, container_id: String) -> anyhow::Result<Vec<IpAddr>> {
        let request = tonic::Request::new(ExecSyncRequest {
            container_id,
            cmd: vec!["cat".to_string(), "/proc/net/if_inet6".to_string()],
            timeout: 0,
        });

        let response = self.cri.clone().exec_sync(request).await.unwrap();

        let result = String::from_utf8(response.get_ref().stdout.clone()).unwrap();

        let mut ip_addresses: Vec<IpAddr> = vec![];

        result.lines().for_each(|line| {
            let ip_str = format!(
                "{}:{}:{}:{}:{}:{}:{}:{}",
                &line[0..4],
                &line[4..8],
                &line[8..12],
                &line[12..16],
                &line[16..20],
                &line[20..24],
                &line[24..28],
                &line[28..32]
            );
            let interface = line.split_whitespace().last().unwrap();
            if interface != "lo" {
                println!("{} {}", ip_str, interface);
                let ip_address = ip_str.parse::<IpAddr>().unwrap();

                ip_addresses.push(ip_address)
            }
        });

        Ok(ip_addresses)
    }

    pub(super) async fn container_events(&self) -> BoxStream<'_, ContainerEvent> {
        let request = tonic::Request::new(GetEventsRequest {});
        let response = self
            .cri
            .clone()
            .get_container_events(request)
            .await
            .unwrap();

        let container_events = response.into_inner();

        Box::pin(container_events.map(|event| {
            let event = event.unwrap();
            ContainerEvent {
                id: event.container_id.clone(),
                action: match event.container_event_type {
                    0 => ContainerAction::Unknown,
                    1 => ContainerAction::Unpause,
                    2 => ContainerAction::Pause,
                    3 => ContainerAction::Die,
                    _ => ContainerAction::Unknown,
                },
            }
        }))
    }
}
