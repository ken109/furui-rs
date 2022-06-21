use std::sync::Arc;

use aya::Bpf;
use tokio::sync::Mutex;
use tracing::info;

use furui_common::{Connect6Event, ConnectEvent};

use crate::handle::{handle_perf_array, to_str};

pub async fn connect(bpf: Arc<Mutex<Bpf>>) -> anyhow::Result<()> {
    handle_perf_array(bpf, "CONNECT_EVENTS", |event: ConnectEvent| async move {
        info!(
            container_id = to_str(event.container_id).as_str(),
            pid = event.pid,
            comm = to_str(event.comm).as_str(),
            protocol = format!("{}{}", event.protocol(), event.family()).as_str(),
            source_addr = event.src_addr().as_str(),
            source_port = event.src_port,
            destination_addr = event.dst_addr().as_str(),
            destination_port = event.dst_port,
        );
    })
    .await?;

    Ok(())
}

pub async fn connect6(bpf: Arc<Mutex<Bpf>>) -> anyhow::Result<()> {
    handle_perf_array(bpf, "CONNECT6_EVENTS", |event: Connect6Event| async move {
        info!(
            container_id = to_str(event.container_id).as_str(),
            pid = event.pid,
            comm = to_str(event.comm).as_str(),
            protocol = format!("{}{}", event.protocol(), event.family()).as_str(),
            source_addr = event.src_addr().as_str(),
            source_port = event.src_port,
            destination_addr = event.dst_addr().as_str(),
            destination_port = event.dst_port,
        );
    })
    .await?;

    Ok(())
}
