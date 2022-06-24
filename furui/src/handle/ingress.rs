use std::ops::Deref;
use std::sync::Arc;

use aya::Bpf;
use furui_common::IngressEvent;
use tokio::sync::Mutex;
use tracing::info;

use crate::handle::{handle_perf_array, to_str, PidProcesses};
use crate::Maps;

pub async fn ingress(bpf: Arc<Mutex<Bpf>>) -> anyhow::Result<()> {
    let args = Arc::new(Mutex::new(()));

    handle_perf_array(
        bpf,
        "INGRESS_EVENTS",
        args,
        |event: IngressEvent, _| async move {
            info!(
                action = event.action.to_string().as_str(),
                comm = to_str(event.comm).as_str(),
                protocol = event.protocol().as_str(),
                source_addr = event.src_addr().as_str(),
                source_port = event.sport,
                destination_addr = event.dst_addr().as_str(),
                destination_port = event.dport,
            );
        },
    )
    .await?;

    Ok(())
}
