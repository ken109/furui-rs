use std::sync::Arc;

use aya::Bpf;
use tokio::sync::Mutex;
use tracing::info;

use furui_common::BindEvent;

use crate::handle::ebpf::{c_char_array_to_str, handle_perf_array, u8_array_to_str, PidProcesses};

pub async fn bind(
    bpf: Arc<Mutex<Bpf>>,
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
                pid_processes.add(
                    event.pid,
                    c_char_array_to_str(event.container_id),
                    event.lport,
                    event.protocol,
                );
            }

            info!(
                event = "bind",
                container_id = c_char_array_to_str(event.container_id).as_str(),
                pid = event.pid,
                comm = u8_array_to_str(event.comm).as_str(),
                family = event.family.to_string(),
                protocol = event.protocol.to_string(),
                lport = event.lport,
            );
        },
    )
    .await?;

    Ok(())
}
