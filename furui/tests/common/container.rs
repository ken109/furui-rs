use std::net::IpAddr;

use bollard::{
    models::ContainerCreateBody,
    query_parameters::{CreateContainerOptionsBuilder, RemoveContainerOptionsBuilder},
    Docker,
};

/// A container created for the duration of one test.
pub struct Container {
    pub id: String,
    pub addresses: Vec<IpAddr>,
}

impl Container {
    /// Creates and starts `image` under `name`, replacing any leftover
    /// container from an earlier run.
    pub async fn start(name: &str, image: &str) -> Container {
        let docker = Docker::connect_with_local_defaults().expect("failed to connect to docker");

        // A previous run that panicked will have left this behind.
        let _ = docker
            .remove_container(
                name,
                Some(RemoveContainerOptionsBuilder::new().force(true).build()),
            )
            .await;

        let created = docker
            .create_container(
                Some(CreateContainerOptionsBuilder::new().name(name).build()),
                ContainerCreateBody {
                    image: Some(image.to_string()),
                    ..Default::default()
                },
            )
            .await
            .expect("failed to create container");

        docker
            .start_container(&created.id, None)
            .await
            .expect("failed to start container");

        let inspect = docker
            .inspect_container(&created.id, None)
            .await
            .expect("failed to inspect container");

        let mut addresses = vec![];
        for (_, network) in inspect
            .network_settings
            .and_then(|settings| settings.networks)
            .unwrap_or_default()
        {
            for addr in [network.ip_address, network.global_ipv6_address]
                .into_iter()
                .flatten()
            {
                if let Ok(addr) = addr.parse::<IpAddr>() {
                    addresses.push(addr);
                }
            }
        }

        Container {
            id: created.id,
            addresses,
        }
    }

    /// The first IPv4 address, formatted as an HTTP URL.
    pub fn ipv4_url(&self) -> String {
        let addr = self
            .addresses
            .iter()
            .find(|addr| addr.is_ipv4())
            .expect("container has no IPv4 address");
        format!("http://{addr}")
    }

    pub async fn remove(&self) {
        let docker = Docker::connect_with_local_defaults().expect("failed to connect to docker");

        docker
            .remove_container(
                &self.id,
                Some(RemoveContainerOptionsBuilder::new().force(true).build()),
            )
            .await
            .expect("failed to remove container");
    }
}
