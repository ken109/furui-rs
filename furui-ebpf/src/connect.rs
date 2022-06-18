use core::mem::MaybeUninit;

use aya_bpf::cty::c_long;
use aya_bpf::helpers::bpf_probe_read_kernel;
use aya_bpf::maps::PerfEventArray;
use aya_bpf::{
    macros::{kprobe, map},
    programs::ProbeContext,
    BpfContext,
};

use furui_common::{Connect6Event, ConnectEvent, PortKey, PortVal};

use crate::helpers::{
    get_container_id, is_container_process, ntohl, ntohs, AF_INET, AF_INET6, IPPROTO_TCP,
};
use crate::vmlinux::{inet_sock, sock};
use crate::PROC_PORTS;

#[map]
static mut CONNECT_EVENTS: PerfEventArray<ConnectEvent> =
    PerfEventArray::<ConnectEvent>::with_max_entries(1024, 0);

#[map]
static mut CONNECT6_EVENTS: PerfEventArray<Connect6Event> =
    PerfEventArray::<Connect6Event>::with_max_entries(1024, 0);

#[kprobe]
pub fn tcp_connect(ctx: ProbeContext) -> u32 {
    match unsafe { try_tcp_connect(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

unsafe fn try_tcp_connect(ctx: ProbeContext) -> Result<u32, c_long> {
    if !is_container_process()? {
        return Ok(0);
    }

    let sk = &*bpf_probe_read_kernel(&ctx.arg::<*const sock>(0).ok_or(1)?)?;
    let family = bpf_probe_read_kernel(&sk.__sk_common.skc_family)?;

    // Only IPv4 & IPv6 is supported.
    if family != AF_INET && family != AF_INET6 {
        return Ok(0);
    }

    let isk = &*(sk as *const sock).cast::<inet_sock>();
    let sport = ntohs(bpf_probe_read_kernel(&isk.inet_sport)?);

    let mut key_uninit = MaybeUninit::<PortKey>::zeroed();
    let mut key_ptr = key_uninit.as_mut_ptr();

    (*key_ptr).container_id = get_container_id()?;
    (*key_ptr).port = sport;
    (*key_ptr).proto = IPPROTO_TCP;

    PROC_PORTS.insert(
        key_uninit.assume_init_ref(),
        &PortVal {
            comm: ctx.command()?,
        },
        0,
    )?;

    if family == AF_INET {
        let mut event_uninit = MaybeUninit::<ConnectEvent>::zeroed();
        let mut event_ptr = event_uninit.as_mut_ptr();

        (*event_ptr).container_id = get_container_id()?;
        (*event_ptr).pid = ctx.pid();
        (*event_ptr).comm = ctx.command()?;
        (*event_ptr).src_addr = ntohl(bpf_probe_read_kernel(
            &sk.__sk_common
                .__bindgen_anon_1
                .__bindgen_anon_1
                .skc_rcv_saddr,
        )?);
        (*event_ptr).dst_addr = ntohl(bpf_probe_read_kernel(
            &sk.__sk_common.__bindgen_anon_1.__bindgen_anon_1.skc_daddr,
        )?);
        (*event_ptr).src_port = sport;
        (*event_ptr).dst_port = ntohs(bpf_probe_read_kernel(
            &sk.__sk_common.__bindgen_anon_3.__bindgen_anon_1.skc_dport,
        )?);
        (*event_ptr).family = family;
        (*event_ptr).protocol = IPPROTO_TCP;

        CONNECT_EVENTS.output(&ctx, event_uninit.assume_init_ref(), 0);
    } else if family == AF_INET6 {
        let np = &*bpf_probe_read_kernel(&isk.pinet6)?;

        let mut event_uninit = MaybeUninit::<Connect6Event>::zeroed();
        let mut event_ptr = event_uninit.as_mut_ptr();

        (*event_ptr).container_id = get_container_id()?;
        (*event_ptr).pid = ctx.pid();
        (*event_ptr).comm = ctx.command()?;
        (*event_ptr).src_addr = bpf_probe_read_kernel(&np.saddr.in6_u.u6_addr8)?;
        (*event_ptr).dst_addr =
            bpf_probe_read_kernel(&isk.sk.__sk_common.skc_v6_daddr.in6_u.u6_addr8)?;
        (*event_ptr).src_port = sport;
        (*event_ptr).dst_port = ntohs(bpf_probe_read_kernel(
            &sk.__sk_common.__bindgen_anon_3.__bindgen_anon_1.skc_dport,
        )?);
        (*event_ptr).family = family;
        (*event_ptr).protocol = IPPROTO_TCP;

        CONNECT6_EVENTS.output(&ctx, event_uninit.assume_init_ref(), 0);
    }

    Ok(0)
}

#[kprobe]
pub fn udp_connect_v4(ctx: ProbeContext) -> u32 {
    match unsafe { try_udp_connect_v4(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

unsafe fn try_udp_connect_v4(_ctx: ProbeContext) -> Result<u32, c_long> {
    Ok(0)
}

#[kprobe]
pub fn udp_connect_v6(ctx: ProbeContext) -> u32 {
    match unsafe { try_udp_connect_v6(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

unsafe fn try_udp_connect_v6(_ctx: ProbeContext) -> Result<u32, c_long> {
    Ok(0)
}
