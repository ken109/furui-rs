use std::collections::HashMap;
use std::convert::TryFrom;
use std::net::IpAddr;
use std::sync::Arc;

use anyhow::anyhow;
use bollard;
use bollard::container::ListContainersOptions;
use bollard::system::EventsOptions;
use futures::stream::BoxStream;
use futures::StreamExt;
use serde_yaml::Value;
use tokio::net::UnixStream;
use tokio::sync::Mutex;
use tonic::transport::{Channel, Endpoint, Uri};
use tower::service_fn;

use furui_common::CONTAINER_ID_LEN;
use k8s_cri::{
    runtime_service_client::RuntimeServiceClient, ContainerFilter, ContainerState,
    ListContainersRequest,
};

use crate::domain::{Container, Containers};
use crate::runtime::k8s_cri::{
    ContainerStateValue, ContainerStatusRequest, ExecSyncRequest, GetEventsRequest,
};
use crate::{ContainerRuntime, Options};

pub mod k8s_cri {
    use tonic;

    tonic::include_proto!("runtime.v1");
}

#[derive(Debug)]
pub struct ContainerEvent {
    pub id: String,
    pub action: ContainerAction,
}

#[derive(Debug)]
pub enum ContainerAction {
    Start,
    Pause,
    Unpause,
    Die,
    Unknown,
}

pub struct Runtime {
    engine_type: ContainerRuntime,
    docker: Option<RuntimeDocker>,
    kubernetes_cri: Option<RuntimeKubernetesCri>,
}

impl Runtime {
    pub async fn new(opt: &Options) -> anyhow::Result<Arc<Runtime>> {
        match opt.container_engine {
            ContainerRuntime::Docker => Ok(Arc::new(Runtime {
                engine_type: opt.container_engine.clone(),
                docker: Some(RuntimeDocker::new().await?),
                kubernetes_cri: None,
            })),
            ContainerRuntime::KubernetesCri => Ok(Arc::new(Runtime {
                engine_type: opt.container_engine.clone(),
                docker: None,
                kubernetes_cri: Some(RuntimeKubernetesCri::new().await?),
            })),
        }
    }

    async fn container_ids(&self) -> anyhow::Result<Vec<String>> {
        match &self.engine_type {
            ContainerRuntime::Docker => self.docker.as_ref().unwrap().container_ids().await,
            ContainerRuntime::KubernetesCri => {
                self.kubernetes_cri.as_ref().unwrap().container_ids().await
            }
        }
    }

    pub async fn set_container_inspect(&self, container: &mut Container) -> anyhow::Result<()> {
        container.id = Some(
            container
                .id
                .as_ref()
                .unwrap()
                .chars()
                .take(CONTAINER_ID_LEN)
                .collect::<String>(),
        );
        match &self.engine_type {
            ContainerRuntime::Docker => {
                self.docker
                    .as_ref()
                    .unwrap()
                    .set_container_inspect(container)
                    .await
            }
            ContainerRuntime::KubernetesCri => {
                self.kubernetes_cri
                    .as_ref()
                    .unwrap()
                    .set_container_inspect(container)
                    .await
            }
        }
    }

    pub async fn add_running_containers_inspect(
        &self,
        containers: Arc<Mutex<Containers>>,
    ) -> anyhow::Result<()> {
        let container_ids = self.container_ids().await?;

        for container_id in container_ids {
            let mut container = Container::new(container_id);

            self.set_container_inspect(&mut container).await?;

            containers.lock().await.add(container);
        }

        Ok(())
    }

    pub async fn container_events(&self) -> BoxStream<ContainerEvent> {
        match &self.engine_type {
            ContainerRuntime::Docker => self.docker.as_ref().unwrap().container_events(),
            ContainerRuntime::KubernetesCri => {
                self.kubernetes_cri
                    .as_ref()
                    .unwrap()
                    .container_events()
                    .await
            }
        }
    }
}

struct RuntimeDocker {
    docker: bollard::Docker,
}

impl RuntimeDocker {
    async fn new() -> anyhow::Result<RuntimeDocker> {
        let docker = match bollard::Docker::connect_with_local_defaults() {
            Ok(docker) => docker,
            Err(_) => {
                return Err(anyhow!("Failed to connect to docker."));
            }
        };
        Ok(RuntimeDocker { docker })
    }

    async fn container_ids(&self) -> anyhow::Result<Vec<String>> {
        let mut list_container_filters = HashMap::new();
        list_container_filters.insert("status", vec!["running"]);
        let options = Some(ListContainersOptions {
            all: true,
            filters: list_container_filters,
            ..Default::default()
        });
        let containers = self.docker.list_containers(options).await?;
        Ok(containers.iter().map(|c| c.id.clone().unwrap()).collect())
    }

    async fn set_container_inspect(&self, container: &mut Container) -> anyhow::Result<()> {
        let inspect = self
            .docker
            .inspect_container(&container.id.as_ref().unwrap(), None)
            .await?;

        let mut addrs: Vec<IpAddr> = vec![];
        for (_, network) in inspect.network_settings.unwrap().networks.unwrap() {
            match network.ip_address.unwrap().parse::<IpAddr>() {
                Ok(addr) => addrs.push(addr),
                Err(_) => {}
            };

            match network.global_ipv6_address.unwrap().parse::<IpAddr>() {
                Ok(addr) => addrs.push(addr),
                Err(_) => {}
            };
        }

        container.ip_addresses = Some(addrs);
        container.name = inspect.name.unwrap();
        container.pid = inspect.state.unwrap().pid.unwrap() as u32;

        Ok(())
    }

    fn container_events(&self) -> BoxStream<ContainerEvent> {
        let mut filters = HashMap::new();
        filters.insert("type", vec!["container"]);
        filters.insert("event", vec!["start", "unpause", "pause", "die"]);

        Box::pin(
            self.docker
                .events(Some(EventsOptions {
                    filters,
                    ..Default::default()
                }))
                .map(|event| {
                    let event = event.unwrap();
                    let id = event.actor.unwrap().id.unwrap();
                    let action = match event.action.unwrap().as_str() {
                        "start" => ContainerAction::Start,
                        "unpause" => ContainerAction::Unpause,
                        "pause" => ContainerAction::Pause,
                        "die" => ContainerAction::Die,
                        _ => ContainerAction::Unknown,
                    };
                    ContainerEvent { id, action }
                }),
        )
    }
}

struct RuntimeKubernetesCri {
    cri: RuntimeServiceClient<Channel>,
}

impl RuntimeKubernetesCri {
    async fn new() -> anyhow::Result<RuntimeKubernetesCri> {
        let path = "/run/containerd/containerd.sock";
        let channel = Endpoint::try_from("http://[::]")
            .unwrap()
            .connect_with_connector(service_fn(move |_: Uri| UnixStream::connect(path)))
            .await
            .expect("Could not create client.");

        let client = RuntimeServiceClient::new(channel);
        Ok(RuntimeKubernetesCri { cri: client })
    }

    async fn container_ids(&self) -> anyhow::Result<Vec<String>> {
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

    async fn set_container_inspect(&self, container: &mut Container) -> anyhow::Result<()> {
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

    async fn container_events(&self) -> BoxStream<ContainerEvent> {
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
