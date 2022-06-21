use std::sync::Arc;

use aya::Bpf;
use tokio::sync::Mutex;
use tracing::info;

use crate::handle::handle_perf_array;

pub async fn close(bpf: Arc<Mutex<Bpf>>) -> anyhow::Result<()> {
    handle_perf_array(bpf, "CLOSE_EVENTS", |event: u32| async move {
        info!(pid = event);
    })
    .await?;

    Ok(())
}
