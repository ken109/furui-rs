use std::sync::Arc;

use aya::Bpf;
use furui_common::{Ingress6Event, Ingress6IcmpEvent, IngressEvent, IngressIcmpEvent};
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
                action = event.action.to_string(),
                container_id = to_str(event.container_id).as_str(),
                comm = to_str(event.comm).as_str(),
                family = event.family.to_string(),
                protocol = event.protocol.to_string(),
                source_addr = event.src_addr().as_str(),
                source_port = event.sport,
                destination_addr = event.dst_addr().as_str(),
                destination_port = event.dport,
            );
        },
    )
    .await?;

    handle_perf_array(
        bpf.clone(),
        "INGRESS_ICMP_EVENTS",
        args.clone(),
        |event: IngressIcmpEvent, _| async move {
            info!(
                event = "ingress",
                action = event.action.to_string(),
                container_id = to_str(event.container_id).as_str(),
                family = event.family.to_string(),
                protocol = event.protocol.to_string(),
                source_addr = event.src_addr().as_str(),
                destination_addr = event.dst_addr().as_str(),
                version = event.version.to_string(),
                "type" = event.type_,
                code = event.code,
            );
        },
    )
    .await?;

    handle_perf_array(
        bpf.clone(),
        "INGRESS6_EVENTS",
        args.clone(),
        |event: Ingress6Event, _| async move {
            info!(
                event = "ingress",
                action = event.action.to_string(),
                container_id = to_str(event.container_id).as_str(),
                comm = to_str(event.comm).as_str(),
                family = event.family.to_string(),
                protocol = event.protocol.to_string(),
                source_addr = event.src_addr().as_str(),
                source_port = event.sport,
                destination_addr = event.dst_addr().as_str(),
                destination_port = event.dport,
            );
        },
    )
    .await?;

    handle_perf_array(
        bpf.clone(),
        "INGRESS6_ICMP_EVENTS",
        args.clone(),
        |event: Ingress6IcmpEvent, _| async move {
            info!(
                event = "ingress",
                action = event.action.to_string(),
                container_id = to_str(event.container_id).as_str(),
                family = event.family.to_string(),
                protocol = event.protocol.to_string(),
                source_addr = event.src_addr().as_str(),
                destination_addr = event.dst_addr().as_str(),
                version = event.version.to_string(),
                "type" = event.type_,
                code = event.code,
            );
        },
    )
    .await?;

    Ok(())
}
