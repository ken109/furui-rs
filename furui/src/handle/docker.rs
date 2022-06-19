use std::sync::Arc;

use futures::StreamExt;
use tokio::sync::Mutex;
use tokio::task;
use tracing::{info, warn};

use crate::domain::Container;
use crate::{Containers, Docker};

pub fn docker_events(docker: Arc<Docker>, containers: Arc<Mutex<Containers>>) {
    let container_events = docker.container_events();

    task::spawn(async move {
        futures::pin_mut!(container_events);

        while let Some(Ok(event)) = container_events.next().await {
            match event.action.unwrap().as_str() {
                "start" | "unpause" => {
                    add_container(
                        docker.clone(),
                        event.actor.unwrap().id.unwrap(),
                        containers.clone(),
                    )
                    .await
                }
                "pause" | "die" => {
                    remove_container(
                        docker.clone(),
                        event.actor.unwrap().id.unwrap(),
                        containers.clone(),
                    )
                    .await
                }
                _ => {}
            }
        }
    });
}

async fn add_container(docker: Arc<Docker>, id: String, containers: Arc<Mutex<Containers>>) {
    let mut container = Container::new(id);

    docker
        .set_container_inspect(&mut container)
        .await
        .unwrap_or_else(|e| {
            warn!("failed to add the container inspection: {}", e);
        });

    println!("{:?}", containers);

    containers.lock().await.add(container);

    println!("{:?}", containers);
}

async fn remove_container(docker: Arc<Docker>, id: String, containers: Arc<Mutex<Containers>>) {}
