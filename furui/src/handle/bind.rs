use std::collections::HashMap;
use std::sync::Arc;

use aya::Bpf;
use tokio::sync::Mutex;
use tracing::info;

use furui_common::BindEvent;

use crate::domain::Process;
use crate::handle::{handle_perf_array, to_str, PidProcesses};

pub async fn bind(
    bpf: Arc<Mutex<Bpf>>,
    _pid_processes: Arc<Mutex<PidProcesses>>,
) -> anyhow::Result<()> {
    // let pid_processes = pid_processes.clone();

    handle_perf_array(bpf, "BIND_EVENTS", |event: BindEvent| async move {
        // unsafe {
        //     pid_processes.lock().await.add(
        //         event.pid,
        //         to_str(event.container_id),
        //         event.lport,
        //         event.protocol,
        //     );
        // }

        info!(
            container_id = to_str(event.container_id).as_str(),
            pid = event.pid,
            comm = to_str(event.comm).as_str(),
            protocol = format!("{}{}", event.protocol(), event.family()).as_str(),
            lport = event.lport,
        );
    })
    .await?;

    Ok(())
}
