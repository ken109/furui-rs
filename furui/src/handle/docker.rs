use futures::StreamExt;

use crate::Docker;

pub async fn docker(docker: &Docker) {
    let container_events = docker.container_events();

    futures::pin_mut!(container_events);

    while let Some(Ok(event)) = container_events.next().await {
        println!("{:#?}", event);
    }
}
