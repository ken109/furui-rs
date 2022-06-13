use futures::StreamExt;

use crate::Docker;

pub async fn docker(docker: &Docker) {
    let mut container_events = docker.container_events();

    futures::pin_mut!(container_events);

    while let Some(event) = container_events.next().await {
        println!("{:#?}", event);
    }
}
