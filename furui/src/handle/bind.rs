use aya::Bpf;
use chrono::Local;
use log::info;

use furui_common::BindEvent;

use crate::handle::{handle_perf_array, to_str};

pub fn bind(bpf: &mut Bpf) -> anyhow::Result<()> {
    handle_perf_array(
        bpf,
        "BIND_EVENTS",
        Box::new(|event: BindEvent| {
            let time = Local::now().format("%H:%M:%S").to_string();

            info!(
                "{} {} PID {} {} {} {} {}",
                time,
                to_str(event.container_id),
                event.pid,
                to_str(event.comm),
                event.family,
                event.lport,
                event.proto,
            );
        }),
    )?;

    Ok(())
}
