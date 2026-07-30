use std::sync::Arc;

use aya::Ebpf;
use furui_common::{Connect6Event, ConnectEvent};
use tokio::sync::Mutex;
use tracing::info;

use crate::bpf::events::{handle_perf_array, PidProcesses};

pub async fn connect(
    bpf: Arc<Mutex<Ebpf>>,
    pid_processes: Arc<Mutex<PidProcesses>>,
) -> anyhow::Result<()> {
    handle_perf_array(
        bpf.clone(),
        "CONNECT_EVENTS",
        pid_processes.clone(),
        |event: ConnectEvent, pid_processes| async move {
            let mut pid_processes = pid_processes.lock().await;

            pid_processes.add(
                event.pid,
                event.container_id(),
                event.src_port,
                event.protocol,
            );

            info!(
                event = "connect",
                container_id = event.container_id().as_str(),
                pid = event.pid,
                comm = event.comm().as_str(),
                family = event.family.to_string(),
                protocol = event.protocol.to_string(),
                source_addr = event.src_addr().as_str(),
                source_port = event.src_port,
                destination_addr = event.dst_addr().as_str(),
                destination_port = event.dst_port,
            );
        },
    )
    .await?;

    handle_perf_array(
        bpf,
        "CONNECT6_EVENTS",
        pid_processes,
        |event: Connect6Event, pid_processes| async move {
            let mut pid_processes = pid_processes.lock().await;

            pid_processes.add(
                event.pid,
                event.container_id(),
                event.src_port,
                event.protocol,
            );

            info!(
                event = "connect",
                container_id = event.container_id().as_str(),
                pid = event.pid,
                comm = event.comm().as_str(),
                family = event.family.to_string(),
                protocol = event.protocol.to_string(),
                source_addr = event.src_addr().as_str(),
                source_port = event.src_port,
                destination_addr = event.dst_addr().as_str(),
                destination_port = event.dst_port,
            );
        },
    )
    .await?;

    Ok(())
}
