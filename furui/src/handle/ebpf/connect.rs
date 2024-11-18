use std::sync::Arc;

use aya::Ebpf;
use furui_common::{Connect6Event, ConnectEvent};
use tokio::sync::Mutex;
use tracing::info;

use crate::handle::ebpf::{handle_perf_array, PidProcesses};

pub async fn connect(
    bpf: Arc<Mutex<Ebpf>>,
    pid_processes: Arc<Mutex<PidProcesses>>,
) -> anyhow::Result<()> {
    let args = Arc::new(Mutex::new(pid_processes));

    handle_perf_array(
        bpf.clone(),
        "CONNECT_EVENTS",
        args.clone(),
        |event: ConnectEvent, args| async move {
            let args = args.lock().await;
            let mut pid_processes = args.lock().await;

            unsafe {
                pid_processes.add(
                    event.pid,
                    event.container_id(),
                    event.src_port,
                    event.protocol,
                );
            }

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
        args,
        |event: Connect6Event, args| async move {
            let args = args.lock().await;
            let mut pid_processes = args.lock().await;

            unsafe {
                pid_processes.add(
                    event.pid,
                    event.container_id(),
                    event.src_port,
                    event.protocol,
                );
            }

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
