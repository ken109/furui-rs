#![no_std]
#![no_main]

use aya_bpf::{
    macros::kprobe,
    programs::ProbeContext,
};

#[kprobe(name = "tcp_connect")]
pub fn tcp_connect(ctx: ProbeContext) -> u32 {
    match unsafe { try_tcp_connect(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_tcp_connect(_ctx: ProbeContext) -> Result<u32, u32> {
    Ok(0)
}


#[kprobe(name = "udp_connect_v4")]
pub fn udp_connect_v4(ctx: ProbeContext) -> u32 {
    match unsafe { try_udp_connect_v4(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_udp_connect_v4(_ctx: ProbeContext) -> Result<u32, u32> {
    Ok(0)
}


#[kprobe(name = "udp_connect_v6")]
pub fn udp_connect_v6(ctx: ProbeContext) -> u32 {
    match unsafe { try_udp_connect_v6(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_udp_connect_v6(_ctx: ProbeContext) -> Result<u32, u32> {
    Ok(0)
}


#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
