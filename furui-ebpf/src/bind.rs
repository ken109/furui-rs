use aya_ebpf::{
    cty::c_long,
    helpers::bpf_probe_read_kernel,
    macros::{kprobe, map},
    maps::PerfEventArray,
    programs::ProbeContext,
    EbpfContext,
};
use aya_log_ebpf::warn;
use furui_common::{BindEvent, EthProtocol, IpProtocol, PortKey, PortVal};

use crate::{
    helpers::{get_container_id, is_container_process, ntohs},
    vmlinux::{sockaddr_in, sockaddr_in6, socket},
    PROC_PORTS,
};

#[map]
static BIND_EVENTS: PerfEventArray<BindEvent> = PerfEventArray::<BindEvent>::new(0);

#[kprobe]
pub fn bind_v4(ctx: ProbeContext) -> u32 {
    match unsafe { try_bind_v4(&ctx) } {
        Ok(ret) => ret,
        Err(ret) => {
            if ret != 0 {
                warn!(&ctx, "bind event failed in kernel: {}", ret);
            }
            ret as u32
        }
    }
}

unsafe fn try_bind_v4(ctx: &ProbeContext) -> Result<u32, c_long> {
    if !is_container_process()? {
        return Ok(0);
    }

    let mut event: BindEvent = core::mem::zeroed();

    event.container_id = get_container_id()?;
    event.pid = ctx.pid();
    event.comm = ctx.command()?;

    let sock = &*bpf_probe_read_kernel(&ctx.arg::<*const socket>(0).ok_or(1)?)?;
    let sk = &*bpf_probe_read_kernel(&sock.sk)?;
    event.family = EthProtocol::from_family(bpf_probe_read_kernel(&sk.__sk_common.skc_family)?);

    if event.family.is_ip() {
        let in_addr = &*bpf_probe_read_kernel(&ctx.arg::<*const sockaddr_in>(1).ok_or(1)?)?;
        event.lport = ntohs(bpf_probe_read_kernel(&in_addr.sin_port)?);
        event.protocol = IpProtocol::new(bpf_probe_read_kernel(&sk.sk_protocol)? as u8);

        finish_bind(&ctx, &event)?;
    }

    Ok(0)
}

#[kprobe]
pub fn bind_v6(ctx: ProbeContext) -> u32 {
    match unsafe { try_bind_v6(&ctx) } {
        Ok(ret) => ret,
        Err(ret) => {
            if ret != 0 {
                warn!(&ctx, "bind6 event failed in kernel: {}", ret);
            }
            ret as u32
        }
    }
}

unsafe fn try_bind_v6(ctx: &ProbeContext) -> Result<u32, c_long> {
    if !is_container_process()? {
        return Ok(0);
    }

    let mut event: BindEvent = core::mem::zeroed();

    event.container_id = get_container_id()?;
    event.pid = ctx.pid();
    event.comm = ctx.command()?;

    let sock = &*bpf_probe_read_kernel(&ctx.arg::<*const socket>(0).ok_or(1)?)?;
    let sk = &*bpf_probe_read_kernel(&sock.sk)?;
    event.family = EthProtocol::from_family(bpf_probe_read_kernel(&sk.__sk_common.skc_family)?);

    if event.family.is_ipv6() {
        let in_addr = &*bpf_probe_read_kernel(&ctx.arg::<*const sockaddr_in6>(1).ok_or(1)?)?;
        event.lport = ntohs(bpf_probe_read_kernel(&in_addr.sin6_port)?);
        event.protocol = IpProtocol::new(bpf_probe_read_kernel(&sk.sk_protocol)? as u8);

        finish_bind(ctx, &event)?;
    }

    Ok(0)
}

unsafe fn finish_bind(ctx: &ProbeContext, event: &BindEvent) -> Result<(), c_long> {
    PROC_PORTS.insert(
        &PortKey {
            container_id: event.container_id,
            port: event.lport,
            proto: event.protocol,
        },
        &PortVal { comm: event.comm },
        0,
    )?;

    BIND_EVENTS.output(ctx, event, 0);

    Ok(())
}
