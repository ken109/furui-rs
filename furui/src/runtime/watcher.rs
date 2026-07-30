use std::sync::Arc;

use futures::StreamExt;
use tokio::{sync::RwLock, task};
use tracing::{info, warn};

use crate::{
    bpf::{Loader, Maps},
    domain::{Container, Containers, Policies},
    runtime::{ContainerAction, Runtime},
};

pub fn watch_containers(
    loader: Arc<Loader>,
    container_engine: Arc<Runtime>,
    maps: Arc<Maps>,
    containers: Arc<RwLock<Containers>>,
    policies: Arc<RwLock<Policies>>,
) {
    task::spawn(async move {
        let cloned_container_engine = container_engine.clone();
        let mut container_events = cloned_container_engine.container_events().await;

        while let Some(event) = container_events.next().await {
            // `Container::new` truncates to the length the maps key on;
            // `Containers::get` accepts a longer id than it stored.
            let id = event.id;

            match event.action {
                ContainerAction::Start | ContainerAction::Unpause => {
                    add_container(
                        loader.clone(),
                        container_engine.clone(),
                        maps.clone(),
                        id,
                        containers.clone(),
                        policies.clone(),
                    )
                    .await
                }
                ContainerAction::Pause | ContainerAction::Die => {
                    remove_container(maps.clone(), id, containers.clone(), policies.clone()).await
                }
                _ => {}
            }
        }
    });
}

async fn add_container(
    loader: Arc<Loader>,
    container_engine: Arc<Runtime>,
    maps: Arc<Maps>,
    id: String,
    containers: Arc<RwLock<Containers>>,
    policies: Arc<RwLock<Policies>>,
) {
    let mut container = Container::new(id.clone());

    container_engine
        .set_container_inspect(&mut container)
        .await
        .unwrap_or_else(|e| warn!("failed to add the container inspection: {}", e));

    containers.write().await.add(container);

    maps.container
        .save_id_with_ips(containers.clone())
        .await
        .unwrap_or_else(|e| warn!("failed to save container: {}", e));

    maps.policy
        .remove()
        .await
        .unwrap_or_else(|e| warn!("failed to remove policies: {}", e));

    policies
        .write()
        .await
        .set_container_id(containers.clone())
        .await;

    maps.policy
        .save(policies.clone())
        .await
        .unwrap_or_else(|e| warn!("failed to save policies: {}", e));

    let _ = loader.attach_tc_programs().await;

    info!(
        container_id = id.as_str(),
        "the container inspection added."
    );
}

async fn remove_container(
    maps: Arc<Maps>,
    id: String,
    containers: Arc<RwLock<Containers>>,
    policies: Arc<RwLock<Policies>>,
) {
    let container = containers.read().await.get(id.clone()).unwrap();

    maps.container
        .remove_id_from_ips(container)
        .await
        .unwrap_or_else(|e| warn!("failed to remove container: {}", e));

    containers.write().await.remove(id.clone());

    maps.policy
        .remove()
        .await
        .unwrap_or_else(|e| warn!("failed to remove policies: {}", e));

    policies
        .write()
        .await
        .set_container_id(containers.clone())
        .await;

    maps.policy
        .save(policies.clone())
        .await
        .unwrap_or_else(|e| warn!("failed to save policies: {}", e));

    info!(
        container_id = id.as_str(),
        "the container inspection removed."
    );
}
