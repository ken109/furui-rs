//! Logging the verdicts the tc classifiers report.
//!
//! Ingress and egress carry the same fields and are logged the same way, so
//! both readers come from one definition; only the event types, the map names
//! and the `event` label differ.

use std::sync::Arc;

use aya::Ebpf;
use furui_common::{
    Egress6Event, Egress6IcmpEvent, EgressEvent, EgressIcmpEvent, Ingress6Event, Ingress6IcmpEvent,
    IngressEvent, IngressIcmpEvent,
};
use tokio::sync::Mutex;
use tracing::info;

use crate::bpf::events::handle_perf_array;

macro_rules! traffic_reader {
    (
        $reader:ident,
        label: $label:literal,
        tcp_udp: [$(($event:ty, $map:literal)),+ $(,)?],
        icmp: [$(($icmp_event:ty, $icmp_map:literal)),+ $(,)?],
    ) => {
        pub async fn $reader(bpf: Arc<Mutex<Ebpf>>) -> anyhow::Result<()> {
            let args = Arc::new(Mutex::new(()));

            $(
                handle_perf_array(
                    bpf.clone(),
                    $map,
                    args.clone(),
                    |event: $event, _| async move {
                        info!(
                            event = $label,
                            action = event.action.to_string(),
                            container_id = event.container_id().as_str(),
                            comm = event.comm().as_str(),
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
            )+

            $(
                handle_perf_array(
                    bpf.clone(),
                    $icmp_map,
                    args.clone(),
                    |event: $icmp_event, _| async move {
                        info!(
                            event = $label,
                            action = event.action.to_string(),
                            container_id = event.container_id().as_str(),
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
            )+

            Ok(())
        }
    };
}

traffic_reader! {
    ingress,
    label: "ingress",
    tcp_udp: [
        (IngressEvent, "INGRESS_EVENTS"),
        (Ingress6Event, "INGRESS6_EVENTS"),
    ],
    icmp: [
        (IngressIcmpEvent, "INGRESS_ICMP_EVENTS"),
        (Ingress6IcmpEvent, "INGRESS6_ICMP_EVENTS"),
    ],
}

traffic_reader! {
    egress,
    label: "egress",
    tcp_udp: [
        (EgressEvent, "EGRESS_EVENTS"),
        (Egress6Event, "EGRESS6_EVENTS"),
    ],
    icmp: [
        (EgressIcmpEvent, "EGRESS_ICMP_EVENTS"),
        (Egress6IcmpEvent, "EGRESS6_ICMP_EVENTS"),
    ],
}
