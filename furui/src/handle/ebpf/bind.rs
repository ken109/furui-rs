use std::sync::Arc;

use aya::Ebpf;
use tokio::sync::Mutex;
use tracing::info;

use furui_common::BindEvent;

use crate::handle::ebpf::{handle_perf_array, PidProcesses};

pub async fn bind(
    bpf: Arc<Mutex<Ebpf>>,
    pid_processes: Arc<Mutex<PidProcesses>>,
) -> anyhow::Result<()> {
    let args = Arc::new(Mutex::new(pid_processes));

    handle_perf_array(
        bpf,
        "BIND_EVENTS",
        args,
        |event: BindEvent, args| async move {
            let arg = args.lock().await;
            let mut pid_processes = arg.lock().await;

            unsafe {
                pid_processes.add(event.pid, event.container_id(), event.lport, event.protocol);
            }

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
