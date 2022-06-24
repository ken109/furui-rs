use aya_bpf::cty::c_long;
use aya_bpf::helpers::bpf_probe_read_kernel;
use aya_bpf::maps::PerfEventArray;
use aya_bpf::{
    macros::{kprobe, map},
    programs::ProbeContext,
    BpfContext,
};

use furui_common::{Connect6Event, ConnectEvent, EthProtocol, IpProtocol, PortKey, PortVal};

use crate::helpers::{get_container_id, is_container_process, ntohl, ntohs};
use crate::vmlinux::{flowi4, flowi6, inet_sock, sock};
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
    let family = EthProtocol::from_family(bpf_probe_read_kernel(&sk.__sk_common.skc_family)?);

    // Only IPv4 & IPv6 is supported.
    if family.is_other() {
        return Ok(0);
    }

    let isk = &*(sk as *const sock).cast::<inet_sock>();
    let sport = ntohs(bpf_probe_read_kernel(&isk.inet_sport)?);

    let mut key: PortKey = core::mem::zeroed();

    key.container_id = get_container_id()?;
    key.port = sport;
    key.proto = IpProtocol::TCP;

    PROC_PORTS.insert(
        &key,
        &PortVal {
            comm: ctx.command()?,
        },
        0,
    )?;

    if family.is_ip() {
        let mut event: ConnectEvent = core::mem::zeroed();

        event.container_id = get_container_id()?;
        event.pid = ctx.pid();
        event.comm = ctx.command()?;
        event.src_addr = ntohl(bpf_probe_read_kernel(
            &sk.__sk_common
                .__bindgen_anon_1
                .__bindgen_anon_1
                .skc_rcv_saddr,
        )?);
        event.dst_addr = ntohl(bpf_probe_read_kernel(
            &sk.__sk_common.__bindgen_anon_1.__bindgen_anon_1.skc_daddr,
        )?);
        event.src_port = sport;
        event.dst_port = ntohs(bpf_probe_read_kernel(
            &sk.__sk_common.__bindgen_anon_3.__bindgen_anon_1.skc_dport,
        )?);
        event.family = family;
        event.protocol = IpProtocol::TCP;

        CONNECT_EVENTS.output(&ctx, &event, 0);
    } else if family.is_ipv6() {
        let np = &*bpf_probe_read_kernel(&isk.pinet6)?;

        let mut event: Connect6Event = core::mem::zeroed();

        event.container_id = get_container_id()?;
        event.pid = ctx.pid();
        event.comm = ctx.command()?;
        event.src_addr = bpf_probe_read_kernel(&np.saddr.in6_u.u6_addr8)?;
        event.dst_addr = bpf_probe_read_kernel(&isk.sk.__sk_common.skc_v6_daddr.in6_u.u6_addr8)?;
        event.src_port = sport;
        event.dst_port = ntohs(bpf_probe_read_kernel(
            &sk.__sk_common.__bindgen_anon_3.__bindgen_anon_1.skc_dport,
        )?);
        event.family = family;
        event.protocol = IpProtocol::TCP;

        CONNECT6_EVENTS.output(&ctx, &event, 0);
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

unsafe fn try_udp_connect_v4(ctx: ProbeContext) -> Result<u32, c_long> {
    if !is_container_process()? {
        return Ok(0);
    }

    let flow4 = &*bpf_probe_read_kernel(&ctx.arg::<*const flowi4>(1).ok_or(1)?)?;
    let sport = ntohs(bpf_probe_read_kernel(&flow4.uli.ports.sport)?);

    let mut key: PortKey = core::mem::zeroed();

    key.container_id = get_container_id()?;
    key.port = sport;
    key.proto = IpProtocol::UDP;

    PROC_PORTS.insert(
        &key,
        &PortVal {
            comm: ctx.command()?,
        },
        0,
    )?;

    let mut event: ConnectEvent = core::mem::zeroed();

    event.container_id = get_container_id()?;
    event.pid = ctx.pid();
    event.comm = ctx.command()?;
    event.src_addr = ntohl(bpf_probe_read_kernel(&flow4.saddr)?);
    event.dst_addr = ntohl(bpf_probe_read_kernel(&flow4.daddr)?);
    event.src_port = sport;
    event.dst_port = ntohs(bpf_probe_read_kernel(&flow4.uli.ports.dport)?);
    event.protocol = IpProtocol::UDP;
    event.family = EthProtocol::IP;

    CONNECT_EVENTS.output(&ctx, &event, 0);

    Ok(0)
}

#[kprobe]
pub fn udp_connect_v6(ctx: ProbeContext) -> u32 {
    match unsafe { try_udp_connect_v6(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

unsafe fn try_udp_connect_v6(ctx: ProbeContext) -> Result<u32, c_long> {
    if !is_container_process()? {
        return Ok(0);
    }

    let flow6 = &*bpf_probe_read_kernel(&ctx.arg::<*const flowi6>(1).ok_or(1)?)?;
    let sport = ntohs(bpf_probe_read_kernel(&flow6.uli.ports.sport)?);

    let mut key: PortKey = core::mem::zeroed();

    key.container_id = get_container_id()?;
    key.port = sport;
    key.proto = IpProtocol::UDP;

    PROC_PORTS.insert(
        &key,
        &PortVal {
            comm: ctx.command()?,
        },
        0,
    )?;

    let mut event: Connect6Event = core::mem::zeroed();

    event.container_id = get_container_id()?;
    event.pid = ctx.pid();
    event.comm = ctx.command()?;
    event.src_addr = bpf_probe_read_kernel(&flow6.saddr.in6_u.u6_addr8)?;
    event.dst_addr = bpf_probe_read_kernel(&flow6.daddr.in6_u.u6_addr8)?;
    event.src_port = sport;
    event.dst_port = ntohs(bpf_probe_read_kernel(&flow6.uli.ports.dport)?);
    event.protocol = IpProtocol::UDP;
    event.family = EthProtocol::IPv6;

    CONNECT6_EVENTS.output(&ctx, &event, 0);

    Ok(0)
}
