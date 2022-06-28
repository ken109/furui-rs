use std::ops::Deref;
use std::sync::Arc;

use aya::Bpf;
use tokio::sync::Mutex;
use tracing::info;

use crate::handle::ebpf::{handle_perf_array, PidProcesses};
use crate::Maps;

pub async fn close(
    bpf: Arc<Mutex<Bpf>>,
    maps: Arc<Maps>,
    pid_processes: Arc<Mutex<PidProcesses>>,
) -> anyhow::Result<()> {
    let args = Arc::new(Mutex::new((maps, pid_processes)));

    handle_perf_array(bpf, "CLOSE_EVENTS", args, |event: u32, args| async move {
        let args = args.lock().await;
        let (maps, pid_processes) = args.deref();
        let mut pid_processes = pid_processes.lock().await;

        match pid_processes.map.get(&event) {
            Some(processes) => unsafe {
                for process in processes {
                    maps.process.remove(process.clone()).await.unwrap_or(());
                }

                pid_processes.map.remove(&event);
                info!(event = "close", pid = event,);
            },
            None => {}
        };
    })
    .await?;

    Ok(())
}
