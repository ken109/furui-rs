use std::{collections::HashMap, net::IpAddr};

use anyhow::anyhow;
use bollard::query_parameters::{EventsOptionsBuilder, ListContainersOptionsBuilder};
use futures::{stream::BoxStream, StreamExt};

use crate::{
    domain::Container,
    runtime::{ContainerAction, ContainerEvent},
};

pub(super) struct RuntimeDocker {
    docker: bollard::Docker,
}

impl RuntimeDocker {
    pub(super) async fn new() -> anyhow::Result<RuntimeDocker> {
        let docker = match bollard::Docker::connect_with_local_defaults() {
            Ok(docker) => docker,
            Err(_) => {
                return Err(anyhow!("Failed to connect to docker."));
            }
        };
        Ok(RuntimeDocker { docker })
    }

    pub(super) async fn container_ids(&self) -> anyhow::Result<Vec<String>> {
        let filters = HashMap::from([("status", vec!["running"])]);
        let options = ListContainersOptionsBuilder::new()
            .all(true)
            .filters(&filters)
            .build();
        let containers = self.docker.list_containers(Some(options)).await?;
        Ok(containers.iter().map(|c| c.id.clone().unwrap()).collect())
    }

    pub(super) async fn set_container_inspect(
        &self,
        container: &mut Container,
    ) -> anyhow::Result<()> {
        let inspect = self
            .docker
            .inspect_container(container.id.as_ref().unwrap(), None)
            .await?;

        let mut addrs: Vec<IpAddr> = vec![];
        for (_, network) in inspect.network_settings.unwrap().networks.unwrap() {
            if let Ok(addr) = network.ip_address.unwrap().parse::<IpAddr>() {
                addrs.push(addr);
            }

            if let Ok(addr) = network.global_ipv6_address.unwrap().parse::<IpAddr>() {
                addrs.push(addr);
            }
        }

        container.ip_addresses = Some(addrs);
        container.name = inspect.name.unwrap();
        container.pid = inspect.state.unwrap().pid.unwrap() as u32;

        Ok(())
    }

    pub(super) fn container_events(&self) -> BoxStream<'_, ContainerEvent> {
        let filters = HashMap::from([
            ("type", vec!["container"]),
            ("event", vec!["start", "unpause", "pause", "die"]),
        ]);
        let options = EventsOptionsBuilder::new().filters(&filters).build();

        Box::pin(self.docker.events(Some(options)).map(|event| {
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
        }))
    }
}
