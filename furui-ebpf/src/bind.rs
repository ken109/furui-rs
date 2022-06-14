#![no_std]
#![no_main]

use core::mem;
use core::mem::MaybeUninit;

use aya_bpf::{
    cty::{c_char, c_void},
    helpers::{bpf_get_current_task, bpf_probe_read, gen},
    macros::{kprobe, map},
    maps::{HashMap, PerfEventArray},
    programs::ProbeContext,
    BpfContext,
};
use aya_log_ebpf::info;

use furui_common::{BindEvent, PortKey, PortVal};

use crate::vmlinux::{socket, task_struct};

#[allow(warnings)]
mod vmlinux;

#[map]
static mut HASH: HashMap<PortKey, PortVal> = HashMap::with_max_entries(1024, 0);

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
    let mut event = MaybeUninit::<BindEvent>::uninit();

    (*event.as_mut_ptr()).pid = ctx.pid();
    (*event.as_mut_ptr()).comm = ctx.command().unwrap();

    let task = &*(bpf_get_current_task() as *const task_struct);

    let nsproxy = &*bpf_probe_read(&task.nsproxy).unwrap();
    let pidns = &*bpf_probe_read(&nsproxy.pid_ns_for_children).unwrap();

    if bpf_probe_read(&pidns.level).unwrap() == 0 {
        return Ok(0);
    }

    let uts = &*bpf_probe_read(&nsproxy.uts_ns).unwrap();

    gen::bpf_probe_read(
        (*event.as_mut_ptr()).container_id.as_mut_ptr() as *mut c_void,
        mem::size_of::<[c_char; 16]>() as u32,
        uts.name.nodename.as_ptr() as *const c_void,
    );

    let _ = (ctx.arg::<*const socket>(0).unwrap()).as_ref().unwrap();

    BIND_EVENTS.output(&ctx, event.assume_init_ref(), 0);

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
