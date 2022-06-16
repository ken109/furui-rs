use aya_bpf::cty::c_ushort;
use aya_bpf::maps::PerfEventArray;
use aya_bpf::{
    macros::{kprobe, map},
    programs::ProbeContext,
    BpfContext,
};

use furui_common::ConnectEvent;

#[map]
static mut CONNECT_EVENTS: PerfEventArray<ConnectEvent> =
    PerfEventArray::<ConnectEvent>::with_max_entries(1024, 0);

#[kprobe]
pub fn tcp_connect(ctx: ProbeContext) -> u32 {
    match unsafe { try_tcp_connect(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

unsafe fn try_tcp_connect(ctx: ProbeContext) -> Result<u32, c_ushort> {
    let pid = ctx.pid();
    let comm = ctx.command().unwrap();

    let event = ConnectEvent { pid, comm };

    CONNECT_EVENTS.output(&ctx, &event, 0);

    Ok(0)
}

#[kprobe]
pub fn udp_connect_v4(ctx: ProbeContext) -> u32 {
    match unsafe { try_udp_connect_v4(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

unsafe fn try_udp_connect_v4(_ctx: ProbeContext) -> Result<u32, c_ushort> {
    Ok(0)
}

#[kprobe]
pub fn udp_connect_v6(ctx: ProbeContext) -> u32 {
    match unsafe { try_udp_connect_v6(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

unsafe fn try_udp_connect_v6(_ctx: ProbeContext) -> Result<u32, c_ushort> {
    Ok(0)
}
