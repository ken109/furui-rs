use std::sync::Arc;

use futures::StreamExt;
use log::info;
use tokio::sync::Mutex;
use tokio::task;
use tracing::warn;

use crate::domain::{Container, Policies};
use crate::{Containers, Docker, Maps};

pub fn docker_events(
    docker: Arc<Docker>,
    maps: Arc<Maps>,
    containers: Arc<Mutex<Containers>>,
    policies: Arc<Mutex<Policies>>,
) {
    let container_events = docker.container_events();

    task::spawn(async move {
        futures::pin_mut!(container_events);

        while let Some(Ok(event)) = container_events.next().await {
            match event.action.unwrap().as_str() {
                "start" | "unpause" => {
                    add_container(
                        docker.clone(),
                        maps.clone(),
                        event.actor.unwrap().id.unwrap(),
                        containers.clone(),
                        policies.clone(),
                    )
                    .await
                }
                "pause" | "die" => {
                    remove_container(
                        maps.clone(),
                        event.actor.unwrap().id.unwrap(),
                        containers.clone(),
                        policies.clone(),
                    )
                    .await
                }
                _ => {}
            }
        }
    });
}

async fn add_container(
    docker: Arc<Docker>,
    maps: Arc<Maps>,
    id: String,
    containers: Arc<Mutex<Containers>>,
    policies: Arc<Mutex<Policies>>,
) {
    let mut container = Container::new(id.clone());

    docker
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
            .remove(policies.clone())
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

    info!("the container inspection added: {}", id.clone());
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
            .remove(policies.clone())
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

    info!("the container inspection removed: {}", id.clone());
}
