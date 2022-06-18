use aya::Bpf;
use tracing::info;

use furui_common::{Connect6Event, ConnectEvent};

use crate::handle::{handle_perf_array, to_str};

pub fn connect(bpf: &mut Bpf) -> anyhow::Result<()> {
    handle_perf_array(
        bpf,
        "CONNECT_EVENTS",
        Box::new(|event: ConnectEvent| {
            info!(
                container_id = to_str(event.container_id).as_str(),
                pid = event.pid,
                comm = to_str(event.comm).as_str(),
                protocol = format!("{}{}", event.protocol(), event.family()).as_str(),
                source_addr = event.src_addr().as_str(),
                source_port = event.src_port,
                destination_addr = event.dst_addr().as_str(),
                destination_port = event.dst_port,
            );
        }),
    )?;

    Ok(())
}

pub fn connect6(bpf: &mut Bpf) -> anyhow::Result<()> {
    handle_perf_array(
        bpf,
        "CONNECT6_EVENTS",
        Box::new(|event: Connect6Event| {
            info!(
                container_id = to_str(event.container_id).as_str(),
                pid = event.pid,
                comm = to_str(event.comm).as_str(),
                protocol = format!("{}{}", event.protocol(), event.family()).as_str(),
                source_addr = event.src_addr().as_str(),
                source_port = event.src_port,
                destination_addr = event.dst_addr().as_str(),
                destination_port = event.dst_port,
            );
        }),
    )?;

    Ok(())
}
