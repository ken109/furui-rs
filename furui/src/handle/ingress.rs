use std::sync::Arc;

use aya::Bpf;
use furui_common::{Ingress6Event, IngressEvent};
use tokio::sync::Mutex;
use tracing::info;

use crate::handle::{handle_perf_array, to_str};

pub async fn ingress(bpf: Arc<Mutex<Bpf>>) -> anyhow::Result<()> {
    let args = Arc::new(Mutex::new(()));

    handle_perf_array(
        bpf.clone(),
        "INGRESS_EVENTS",
        args.clone(),
        |event: IngressEvent, _| async move {
            info!(
                event = "ingress",
                action = event.action.to_string().as_str(),
                container_id = to_str(event.container_id).as_str(),
                comm = to_str(event.comm).as_str(),
                family = event.family.to_string().as_str(),
                protocol = event.protocol.to_string().as_str(),
                source_addr = event.src_addr().as_str(),
                source_port = event.sport,
                destination_addr = event.dst_addr().as_str(),
                destination_port = event.dport,
            );
        },
    )
    .await?;

    handle_perf_array(
        bpf,
        "INGRESS6_EVENTS",
        args,
        |event: Ingress6Event, _| async move {
            info!(
                event = "ingress",
                action = event.action.to_string().as_str(),
                container_id = to_str(event.container_id).as_str(),
                comm = to_str(event.comm).as_str(),
                family = event.family.to_string().as_str(),
                protocol = event.protocol.to_string().as_str(),
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
