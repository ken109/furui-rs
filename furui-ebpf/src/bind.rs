use core::mem::MaybeUninit;

use aya_bpf::helpers::bpf_probe_read_kernel;
use aya_bpf::{
    cty::c_long,
    macros::{kprobe, map},
    maps::PerfEventArray,
    programs::ProbeContext,
    BpfContext,
};

use furui_common::{BindEvent, PortKey, PortVal};

use crate::helpers::{get_container_id, is_container_process, ntohs, AF_INET, AF_INET6};
use crate::vmlinux::{sockaddr_in, sockaddr_in6, socket};
use crate::PROC_PORTS;

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
        let in_addr = &*bpf_probe_read_kernel(&ctx.arg::<*const sockaddr_in>(1).ok_or(1)?)?;
        (*event_ptr).lport = ntohs(bpf_probe_read_kernel(&in_addr.sin_port)?);
        (*event_ptr).protocol = bpf_probe_read_kernel(&sk.sk_protocol)? as u8;

        finish_bind(&ctx, &event_ptr, &event_uninit)?;
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

unsafe fn try_bind_v6(ctx: ProbeContext) -> Result<u32, c_long> {
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

    if (*event_ptr).family == AF_INET6 {
        let in_addr = &*bpf_probe_read_kernel(&ctx.arg::<*const sockaddr_in6>(1).ok_or(1)?)?;
        (*event_ptr).lport = ntohs(bpf_probe_read_kernel(&in_addr.sin6_port)?);
        (*event_ptr).protocol = bpf_probe_read_kernel(&sk.sk_protocol)? as u8;

        finish_bind(&ctx, &event_ptr, &event_uninit)?;
    }

    Ok(0)
}

unsafe fn finish_bind(
    ctx: &ProbeContext,
    ptr: &*mut BindEvent,
    uninit: &MaybeUninit<BindEvent>,
) -> Result<(), c_long> {
    PROC_PORTS.insert(
        &PortKey {
            container_id: (**ptr).container_id,
            port: (**ptr).lport,
            proto: (**ptr).protocol,
        },
        &PortVal { comm: (**ptr).comm },
        0,
    )?;

    BIND_EVENTS.output(ctx, (*uninit).assume_init_ref(), 0);

    Ok(())
}
