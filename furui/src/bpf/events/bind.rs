use std::sync::Arc;

use aya::Ebpf;
use furui_common::BindEvent;
use tokio::sync::Mutex;
use tracing::info;

use crate::bpf::events::{handle_perf_array, PidProcesses};

pub async fn bind(
    bpf: Arc<Mutex<Ebpf>>,
    pid_processes: Arc<Mutex<PidProcesses>>,
) -> anyhow::Result<()> {
    handle_perf_array(
        bpf,
        "BIND_EVENTS",
        pid_processes,
        |event: BindEvent, pid_processes| async move {
            let mut pid_processes = pid_processes.lock().await;

            pid_processes.add(event.pid, event.container_id(), event.lport, event.protocol);

            info!(
                event = "bind",
                container_id = event.container_id().as_str(),
                pid = event.pid,
                comm = event.comm().as_str(),
                family = event.family.to_string(),
                protocol = event.protocol.to_string(),
                lport = event.lport,
            );
        },
    )
    .await?;

    Ok(())
}
