use std::{collections::HashMap, net::IpAddr};

use anyhow::anyhow;
use bollard::query_parameters::{EventsOptionsBuilder, ListContainersOptionsBuilder};
use futures::{stream::BoxStream, StreamExt};
use tracing::warn;

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
        Ok(containers.into_iter().filter_map(|c| c.id).collect())
    }

    pub(super) async fn set_container_inspect(
        &self,
        container: &mut Container,
    ) -> anyhow::Result<()> {
        let id = container
            .id
            .as_ref()
            .ok_or_else(|| anyhow!("cannot inspect a container with no id"))?;
        let inspect = self.docker.inspect_container(id, None).await?;

        // Every field here is optional in the API. A container that reports no
        // networks or no pid is one furui cannot police, so say which one and
        // let the caller decide, rather than panicking inside the event loop.
        let networks = inspect
            .network_settings
            .and_then(|settings| settings.networks)
            .unwrap_or_default();

        let mut addrs: Vec<IpAddr> = vec![];
        for (_, network) in networks {
            for addr in [network.ip_address, network.global_ipv6_address]
                .into_iter()
                .flatten()
            {
                if let Ok(addr) = addr.parse::<IpAddr>() {
                    addrs.push(addr);
                }
            }
        }

        let pid = inspect
            .state
            .and_then(|state| state.pid)
            .ok_or_else(|| anyhow!("container {id} reported no pid"))?;

        container.ip_addresses = Some(addrs);
        container.name = inspect.name.unwrap_or_default();
        container.pid = pid as u32;

        Ok(())
    }

    pub(super) fn container_events(&self) -> BoxStream<'_, ContainerEvent> {
        let filters = HashMap::from([
            ("type", vec!["container"]),
            ("event", vec!["start", "unpause", "pause", "die"]),
        ]);
        let options = EventsOptionsBuilder::new().filters(&filters).build();

        // A malformed or unidentifiable event is dropped rather than taken as
        // an excuse to tear the watcher down.
        Box::pin(
            self.docker
                .events(Some(options))
                .filter_map(|event| async move {
                    let event = match event {
                        Ok(event) => event,
                        Err(err) => {
                            warn!("failed to read a docker event: {err}");
                            return None;
                        }
                    };

                    let id = event.actor.and_then(|actor| actor.id)?;
                    let action = match event.action.as_deref() {
                        Some("start") => ContainerAction::Start,
                        Some("unpause") => ContainerAction::Unpause,
                        Some("pause") => ContainerAction::Pause,
                        Some("die") => ContainerAction::Die,
                        _ => ContainerAction::Unknown,
                    };

                    Some(ContainerEvent { id, action })
                }),
        )
    }
}
