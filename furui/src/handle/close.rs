use aya::Bpf;
use tracing::info;

use crate::handle::handle_perf_array;

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
