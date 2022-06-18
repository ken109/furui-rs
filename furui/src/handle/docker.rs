use futures::StreamExt;
use tokio::task;
use tracing::info;

use crate::Docker;

pub fn docker_events(docker: &Docker) {
    let container_events = docker.container_events();

    task::spawn(async move {
        futures::pin_mut!(container_events);

        while let Some(Ok(event)) = container_events.next().await {
            info!(
                action = event.action.unwrap().as_str(),
                id = event.actor.unwrap().id.unwrap().as_str(),
            );
        }
    });
}
