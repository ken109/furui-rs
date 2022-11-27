use std::sync::Arc;

use futures::StreamExt;
use tokio::sync::Mutex;
use tokio::task;
use tracing::{info, warn};

use furui_common::CONTAINER_ID_LEN;

use crate::domain::{Container, Policies};
use crate::runtime::ContainerAction;
use crate::{Containers, Loader, Maps, Runtime};

pub async fn container_events(
    loader: Arc<Loader>,
    container_engine: Arc<Runtime>,
    maps: Arc<Maps>,
    containers: Arc<Mutex<Containers>>,
    policies: Arc<Mutex<Policies>>,
) {
    task::spawn(async move {
        let cloned_container_engine = container_engine.clone();
        let mut container_events = cloned_container_engine.container_events().await;

        while let Some(event) = container_events.next().await {
            let id = event.id.chars().take(CONTAINER_ID_LEN).collect::<String>();

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
    containers: Arc<Mutex<Containers>>,
    policies: Arc<Mutex<Policies>>,
) {
    let mut container = Container::new(id.clone());

    container_engine
        .set_container_inspect(&mut container)
        .await
        .unwrap_or_else(|e| warn!("failed to add the container inspection: {}", e));

    containers.lock().await.add(container);

    maps.container
        .save_id_with_ips(containers.clone())
        .await
        .unwrap_or_else(|e| warn!("failed to save container: {}", e));

    unsafe {
        maps.policy
            .remove()
            .await
            .unwrap_or_else(|e| warn!("failed to remove policies: {}", e))
    };

    policies
        .lock()
        .await
        .set_container_id(containers.clone())
        .await;

    unsafe {
        maps.policy
            .save(policies.clone())
            .await
            .unwrap_or_else(|e| warn!("failed to save policies: {}", e))
    };

    let _ = loader.attach_tc_programs().await;

    info!(
        container_id = id.as_str(),
        "the container inspection added."
    );
}

async fn remove_container(
    maps: Arc<Maps>,
    id: String,
    containers: Arc<Mutex<Containers>>,
    policies: Arc<Mutex<Policies>>,
) {
    let container = containers.lock().await.get(id.clone()).unwrap();

    maps.container
        .remove_id_from_ips(container)
        .await
        .unwrap_or_else(|e| warn!("failed to remove container: {}", e));

    containers.lock().await.remove(id.clone());

    unsafe {
        maps.policy
            .remove()
            .await
            .unwrap_or_else(|e| warn!("failed to remove policies: {}", e))
    };

    policies
        .lock()
        .await
        .set_container_id(containers.clone())
        .await;

    unsafe {
        maps.policy
            .save(policies.clone())
            .await
            .unwrap_or_else(|e| warn!("failed to save policies: {}", e))
    };

    info!(
        container_id = id.as_str(),
        "the container inspection removed."
    );
}
