use aya::Bpf;
use chrono::Local;
use tracing::info;

use furui_common::BindEvent;

use crate::handle::{handle_perf_array, to_str};

pub fn close(bpf: &mut Bpf) -> anyhow::Result<()> {
    handle_perf_array(
        bpf,
        "CLOSE_EVENTS",
        Box::new(|event: u32| {
            info!(pid = event);
        }),
    )?;

    Ok(())
}
