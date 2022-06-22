use std::ops::Deref;
use std::sync::Arc;

use aya::Bpf;
use tokio::sync::Mutex;
use tracing::info;

use crate::handle::{handle_perf_array, PidProcesses};
use crate::Maps;

pub async fn ingress(bpf: Arc<Mutex<Bpf>>) -> anyhow::Result<()> {
    let args = Arc::new(Mutex::new(()));

    handle_perf_array(bpf, "INGRESS_EVENTS", args, |event: u32, _| async move {
        info!(port = event);
    })
    .await?;

    Ok(())
}
