use aya_bpf::cty::c_long;
use aya_bpf::maps::PerfEventArray;
use aya_bpf::{
    macros::{map, tracepoint},
    programs::TracePointContext,
    BpfContext,
};

use crate::helpers::is_container_process;

#[map]
static mut CLOSE_EVENTS: PerfEventArray<u32> = PerfEventArray::<u32>::with_max_entries(1024, 0);

#[tracepoint]
pub fn close(ctx: TracePointContext) -> u32 {
    match unsafe { try_close(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

unsafe fn try_close(ctx: TracePointContext) -> Result<u32, c_long> {
    if !is_container_process()? {
        return Ok(0);
    }

    CLOSE_EVENTS.output(&ctx, &ctx.pid(), 0);

    Ok(0)
}
