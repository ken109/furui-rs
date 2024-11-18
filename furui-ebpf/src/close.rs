use aya_ebpf::{
    cty::c_long,
    macros::{map, tracepoint},
    maps::PerfEventArray,
    programs::TracePointContext,
    EbpfContext,
};
use aya_log_ebpf::warn;

use crate::helpers::is_container_process;

#[map]
static CLOSE_EVENTS: PerfEventArray<u32> = PerfEventArray::<u32>::new(0);

#[tracepoint]
pub fn close(ctx: TracePointContext) -> u32 {
    match unsafe { try_close(&ctx) } {
        Ok(ret) => ret,
        Err(ret) => {
            if ret != 0 {
                warn!(&ctx, "close event failed in kernel: {}", ret);
            }
            ret as u32
        }
    }
}

unsafe fn try_close(ctx: &TracePointContext) -> Result<u32, c_long> {
    if !is_container_process()? {
        return Ok(0);
    }

    CLOSE_EVENTS.output(ctx, &ctx.pid(), 0);

    Ok(0)
}
