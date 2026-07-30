//! Talking to the container runtime.
//!
//! Enumerating containers, inspecting them for their pid and addresses, and
//! following start/stop events. Docker and the Kubernetes CRI are two
//! implementations of the same operations; [`Runtime`] picks between them and
//! the rest of the crate does not care which is in use.

use std::sync::Arc;

use futures::stream::BoxStream;
use tokio::sync::RwLock;
pub use watcher::watch_containers;

use crate::{
    cli::{ContainerRuntime, Options},
    domain::{Container, Containers},
    runtime::{cri::RuntimeKubernetesCri, docker::RuntimeDocker},
};

mod cri;
mod docker;
mod watcher;

// Generated from `proto/v1.proto` by the build script; not ours to lint.
#[allow(clippy::enum_variant_names)]
pub mod k8s_cri {
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

/// The runtime furui is watching.
///
/// One variant is live; the other backend is not constructed at all. Modelling
/// this as an enum rather than a discriminant beside two `Option`s is what
/// removes the `.as_ref().unwrap()` from every dispatch below.
pub struct Runtime(Backend);

enum Backend {
    Docker(RuntimeDocker),
    KubernetesCri(RuntimeKubernetesCri),
}

impl Runtime {
    pub async fn new(opt: &Options) -> anyhow::Result<Arc<Runtime>> {
        Ok(Arc::new(Runtime(match opt.container_engine {
            ContainerRuntime::Docker => Backend::Docker(RuntimeDocker::new().await?),
            ContainerRuntime::KubernetesCri => {
                Backend::KubernetesCri(RuntimeKubernetesCri::new().await?)
            }
        })))
    }

    async fn container_ids(&self) -> anyhow::Result<Vec<String>> {
        match &self.0 {
            Backend::Docker(docker) => docker.container_ids().await,
            Backend::KubernetesCri(cri) => cri.container_ids().await,
        }
    }

    pub async fn set_container_inspect(&self, container: &mut Container) -> anyhow::Result<()> {
        match &self.0 {
            Backend::Docker(docker) => docker.set_container_inspect(container).await,
            Backend::KubernetesCri(cri) => cri.set_container_inspect(container).await,
        }
    }

    pub async fn add_running_containers_inspect(
        &self,
        containers: Arc<RwLock<Containers>>,
    ) -> anyhow::Result<()> {
        let container_ids = self.container_ids().await?;

        for container_id in container_ids {
            let mut container = Container::new(container_id);

            self.set_container_inspect(&mut container).await?;

            containers.write().await.add(container);
        }

        Ok(())
    }

    pub async fn container_events(&self) -> BoxStream<'_, ContainerEvent> {
        match &self.0 {
            Backend::Docker(docker) => docker.container_events(),
            Backend::KubernetesCri(cri) => cri.container_events().await,
        }
    }
}
