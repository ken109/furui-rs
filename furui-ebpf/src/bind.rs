use core::mem::MaybeUninit;

use aya_bpf::helpers::bpf_probe_read_kernel;
use aya_bpf::{
    cty::{c_long, c_ushort},
    macros::{kprobe, map},
    maps::{HashMap, PerfEventArray},
    programs::ProbeContext,
    BpfContext,
};

use furui_common::{BindEvent, PortKey, PortVal};

use crate::helpers::{get_container_id, is_container_process, AF_INET};
use crate::vmlinux::socket;

#[map]
static mut PROC_PORTS: HashMap<PortKey, PortVal> = HashMap::with_max_entries(1024, 0);

#[map]
static mut BIND_EVENTS: PerfEventArray<BindEvent> =
    PerfEventArray::<BindEvent>::with_max_entries(1024, 0);

#[kprobe]
pub fn bind_v4(ctx: ProbeContext) -> u32 {
    match unsafe { try_bind_v4(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

unsafe fn try_bind_v4(ctx: ProbeContext) -> Result<u32, c_long> {
    if !is_container_process()? {
        return Ok(0);
    }

    let mut event_uninit = MaybeUninit::<BindEvent>::zeroed();
    let mut event_ptr = event_uninit.as_mut_ptr();

    (*event_ptr).container_id = get_container_id()?;
    (*event_ptr).pid = ctx.pid();
    (*event_ptr).comm = ctx.command()?;

    let sock = &*bpf_probe_read_kernel(&ctx.arg::<*const socket>(0).ok_or(1)?)?;
    let sk = &*bpf_probe_read_kernel(&sock.sk)?;
    (*event_ptr).family = bpf_probe_read_kernel(&sk.__sk_common.skc_family)?;

    if (*event_ptr).family == AF_INET {
        // (*event_ptr).lport = 0;
        // (*event_ptr).proto = 0;

        BIND_EVENTS.output(&ctx, event_uninit.assume_init_ref(), 0);
    }

    Ok(0)
}

#[kprobe]
pub fn bind_v6(ctx: ProbeContext) -> u32 {
    match unsafe { try_bind_v6(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

unsafe fn try_bind_v6(_ctx: ProbeContext) -> Result<u32, c_ushort> {
    Ok(0)
}
