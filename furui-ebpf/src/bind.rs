#![no_std]
#![no_main]

use aya_bpf::{BpfContext, macros::{kprobe, map}, maps::PerfEventArray, programs::ProbeContext};

use furui_common::BindEvent;

#[allow(warnings)]
mod vmlinux;


#[map]
static mut BIND_EVENTS: PerfEventArray<BindEvent> = PerfEventArray::<BindEvent>::with_max_entries(1024, 0);

#[kprobe]
pub fn bind_v4(ctx: ProbeContext) -> u32 {
    match unsafe { try_bind_v4(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_bind_v4(ctx: ProbeContext) -> Result<u32, u32> {
    let pid = ctx.pid();
    let comm = ctx.command().unwrap();

    let event = BindEvent {
        pid,
        comm,
    };

    BIND_EVENTS.output(&ctx, &event, 0);

    Ok(0)
}

#[kprobe]
pub fn bind_v6(ctx: ProbeContext) -> u32 {
    match unsafe { try_bind_v6(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_bind_v6(_ctx: ProbeContext) -> Result<u32, u32> {
    Ok(0)
}


#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
