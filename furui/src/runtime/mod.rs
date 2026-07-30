//! Talking to the container runtime.
//!
//! Enumerating containers, inspecting them for their pid and addresses, and
//! following start/stop events. Docker and the Kubernetes CRI are two
//! implementations of the same operations; [`Runtime`] picks between them and
//! the rest of the crate does not care which is in use.

use std::sync::Arc;

use furui_common::CONTAINER_ID_LEN;
use futures::stream::BoxStream;
use tokio::sync::Mutex;
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

    pub async fn container_events(&self) -> BoxStream<'_, ContainerEvent> {
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
