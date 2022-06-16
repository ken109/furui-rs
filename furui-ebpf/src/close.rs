use aya_bpf::cty::c_ushort;
use aya_bpf::{macros::tracepoint, programs::TracePointContext};

#[tracepoint]
pub fn close(ctx: TracePointContext) -> u32 {
    match unsafe { try_close(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

unsafe fn try_close(_ctx: TracePointContext) -> Result<u32, c_ushort> {
    Ok(0)
}
