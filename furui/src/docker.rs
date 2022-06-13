use std::collections::HashMap;
use std::net::IpAddr;

use anyhow::anyhow;
use bollard;
use bollard::container::ListContainersOptions;
use bollard::models::{ContainerInspectResponse, ContainerSummary, EventMessage};
use bollard::system::EventsOptions;
use futures::Stream;
use log::warn;

use crate::constant::CONTAINER_ID_LENGTH;
use crate::domain::{Container, Containers};

pub struct Docker {
    docker: bollard::Docker,
}

impl Docker {
    pub fn new() -> anyhow::Result<Docker> {
        Ok(Docker {
            docker: bollard::Docker::connect_with_local_defaults()?,
        })
    }

    async fn containers(&self) -> anyhow::Result<Vec<ContainerSummary>> {
        let mut list_container_filters = HashMap::new();
        list_container_filters.insert("status", vec!["running"]);

        Ok(self
            .docker
            .list_containers(Some(ListContainersOptions {
                all: true,
                filters: list_container_filters,
                ..Default::default()
            }))
            .await?)
    }

    pub async fn set_container_inspect(&self, container: &mut Container) -> anyhow::Result<()> {
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

        container.id = Some(
            container
                .id
                .as_ref()
                .unwrap()
                .chars()
                .take(CONTAINER_ID_LENGTH)
                .collect::<String>(),
        );
        container.ip_addresses = Some(addrs);
        container.name = inspect.name.unwrap();
        container.pid = inspect.state.unwrap().pid.unwrap();

        Ok(())
    }

    pub async fn add_running_containers_inspect(
        &self,
        containers: &mut Containers,
    ) -> anyhow::Result<()> {
        let docker_containers = self.containers().await?;

        for docker_container in docker_containers {
            let mut container = Container::new(docker_container.id.unwrap());

            self.set_container_inspect(&mut container).await?;

            containers.add(container);
        }

        Ok(())
    }

    pub fn container_events(
        &self,
    ) -> impl Stream<Item = Result<EventMessage, bollard::errors::Error>> {
        let mut filters = HashMap::new();
        filters.insert("type", vec!["container"]);
        filters.insert("event", vec!["start", "unpause", "pause", "die"]);

        self.docker.events(Some(EventsOptions {
            filters,
            ..Default::default()
        }))
    }
}
