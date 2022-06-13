#![no_std]
#![no_main]

use aya_bpf::{macros::tracepoint, programs::TracePointContext};

#[allow(warnings)]
mod vmlinux;

#[tracepoint]
pub fn close(ctx: TracePointContext) -> u32 {
    match unsafe { try_close(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_close(_ctx: TracePointContext) -> Result<u32, u32> {
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
