use bollard::{
    container::{Config, CreateContainerOptions, RemoveContainerOptions, StartContainerOptions},
    Docker,
};

#[derive(Default)]
pub struct Container {
    pub id: String,
    pub ipv4: String,
    pub ipv4_url: String,
    pub ipv6: String,
    pub ipv6_url: String,
}

impl Container {
    pub async fn new(name: &str, image: &str) -> Container {
        let docker = Docker::connect_with_local_defaults().expect("failed to connect to docker");

        let options = CreateContainerOptions {
            name,
            ..Default::default()
        };

        let config = Config {
            image: Some(image),
            ..Default::default()
        };
        let container = docker
            .create_container(Some(options), config)
            .await
            .expect("failed to create container");

        let _ = docker
            .start_container(&container.id, None::<StartContainerOptions<String>>)
            .await;

        let container_inspect = docker
            .inspect_container(&container.id, Default::default())
            .await
            .expect("failed to inspect container");

        let network = container_inspect
            .network_settings
            .unwrap()
            .networks
            .unwrap();

        for (_, network) in network {
            return Container {
                id: container.id.clone(),
                ipv4: network.ip_address.clone().unwrap(),
                ipv4_url: format!("http://{}", network.ip_address.unwrap()),
                ipv6: network.global_ipv6_address.clone().unwrap(),
                ipv6_url: format!("http://[{}]", network.global_ipv6_address.unwrap()),
            };
        }

        return Container::default();
    }

    pub async fn remove(&self) {
        let docker = Docker::connect_with_local_defaults().expect("failed to connect to docker");

        let options = Some(RemoveContainerOptions {
            force: true,
            ..Default::default()
        });

        let id = self.id.clone();

        let _ = docker
            .remove_container(&id, options)
            .await
            .expect("failed to remove container");
    }
}
