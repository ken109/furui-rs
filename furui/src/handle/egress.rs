use std::sync::Arc;

use aya::Bpf;
use tokio::sync::Mutex;
use tracing::info;

use crate::handle::handle_perf_array;

pub async fn egress(bpf: Arc<Mutex<Bpf>>) -> anyhow::Result<()> {
    let args = Arc::new(Mutex::new(()));

    handle_perf_array(bpf, "EGRESS_EVENTS", args, |event: u32, _| async move {
        info!(event = "egress", port = event);
    })
    .await?;

    Ok(())
}
