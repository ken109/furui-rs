use std::sync::Arc;

use aya::Bpf;
use tokio::sync::Mutex;
use tracing::info;

use furui_common::{Connect6Event, ConnectEvent};

use crate::handle::ebpf::{c_char_array_to_str, handle_perf_array, u8_array_to_str, PidProcesses};

pub async fn connect(
    bpf: Arc<Mutex<Bpf>>,
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
                    c_char_array_to_str(event.container_id),
                    event.src_port,
                    event.protocol,
                );
            }

            info!(
                event = "connect",
                container_id = c_char_array_to_str(event.container_id).as_str(),
                pid = event.pid,
                comm = u8_array_to_str(event.comm).as_str(),
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
                    c_char_array_to_str(event.container_id),
                    event.src_port,
                    event.protocol,
                );
            }

            info!(
                event = "connect",
                container_id = c_char_array_to_str(event.container_id).as_str(),
                pid = event.pid,
                comm = u8_array_to_str(event.comm).as_str(),
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
