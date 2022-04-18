#![no_std]
#![no_main]

mod vmlinux;

use aya_bpf::{
    macros::kprobe,
    programs::ProbeContext,
};

#[kprobe(name = "bind_v4")]
pub fn bind_v4(ctx: ProbeContext) -> u32 {
    match unsafe { try_bind_v4(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_bind_v4(_ctx: ProbeContext) -> Result<u32, u32> {
    Ok(0)
}

#[kprobe(name = "bind_v6")]
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
