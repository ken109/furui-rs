#![no_std]
#![no_main]

use aya_bpf::{
    cty::c_char,
    helpers::{bpf_get_current_task, bpf_probe_read},
    macros::{kprobe, map},
    maps::PerfEventArray,
    programs::ProbeContext,
    BpfContext,
};

use furui_common::BindEvent;

use crate::vmlinux::{socket, task_struct};

#[allow(warnings)]
mod vmlinux;

#[map]
static mut BIND_EVENTS: PerfEventArray<BindEvent> =
    PerfEventArray::<BindEvent>::with_max_entries(1024, 0);

#[kprobe]
pub fn bind_v4(ctx: ProbeContext) -> u32 {
    match unsafe { try_bind_v4(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_bind_v4(ctx: ProbeContext) -> Result<u32, u32> {
    let _ = (ctx.arg::<*const socket>(0).unwrap()).as_ref().unwrap();

    let pid = ctx.pid();
    let comm = ctx.command().unwrap();

    let task = (bpf_get_current_task() as *const task_struct)
        .as_ref()
        .unwrap();

    let nsproxy = bpf_probe_read(&task.nsproxy).unwrap().as_ref().unwrap();
    let pidns = bpf_probe_read(&nsproxy.pid_ns_for_children)
        .unwrap()
        .as_ref()
        .unwrap();

    if bpf_probe_read(&pidns.level).unwrap() == 0 {
        return Ok(0);
    }

    let uts = bpf_probe_read(&nsproxy.uts_ns).unwrap().as_ref().unwrap();

    let container_id: [c_char; 65] = bpf_probe_read(&uts.name.nodename).unwrap();
    let container_id = (&container_id[0..12])
        .as_ptr()
        .cast::<[c_char; 12]>()
        .read();

    let event = BindEvent {
        container_id,
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
