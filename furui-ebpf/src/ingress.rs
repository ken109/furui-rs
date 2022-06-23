use aya_bpf::bindings::{TC_ACT_OK, TC_ACT_SHOT};
use aya_bpf::cty::c_long;
use aya_bpf::helpers::bpf_probe_read_kernel;
use aya_bpf::maps::PerfEventArray;
use aya_bpf::{
    macros::{classifier, map},
    programs::SkBuffContext,
};

use furui_common::{
    ContainerID, ContainerIP, EthProtocol, Ingress6Event, IngressEvent, IpProtocol, PortKey,
    TcAction,
};

use crate::helpers::{eth_protocol, ip_protocol, ntohl, ETH_HDR_LEN, IP_HDR_LEN};
use crate::vmlinux::{__sk_buff, ethhdr, icmp6hdr, icmphdr, iphdr, ipv6hdr, tcphdr, udphdr};
use crate::{CONTAINER_ID_FROM_IPS, PROC_PORTS};

#[map]
pub(crate) static mut INGRESS_EVENTS: PerfEventArray<IngressEvent> =
    PerfEventArray::<IngressEvent>::with_max_entries(1024, 0);

#[map]
pub(crate) static mut INGRESS6_EVENTS: PerfEventArray<Ingress6Event> =
    PerfEventArray::<Ingress6Event>::with_max_entries(1024, 0);

#[classifier(name = "ingress")]
pub fn ingress(ctx: SkBuffContext) -> i32 {
    match unsafe { try_ingress(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret as i32,
    }
}

unsafe fn try_ingress(ctx: SkBuffContext) -> Result<i32, c_long> {
    let mut event: IngressEvent = core::mem::zeroed();
    let mut event6: Ingress6Event = core::mem::zeroed();

    let mut id_val: Option<&ContainerID> = core::mem::zeroed();

    let (mut sport, mut dport) = get_port(&ctx)?;
    let eth_proto = eth_protocol(&ctx)?;
    let ip_proto = ip_protocol(&ctx)?;

    match eth_proto {
        EthProtocol::IP => {
            let iph = ctx.load::<iphdr>(ETH_HDR_LEN)?;

            event.saddr = ntohl(iph.saddr);
            event.daddr = ntohl(iph.daddr);
            event.sport = sport;
            event.dport = dport;

            event.protocol = iph.protocol;

            let mut ip_key: ContainerIP = core::mem::zeroed();

            ip_key.ip = event.daddr;

            id_val = CONTAINER_ID_FROM_IPS.get(&ip_key);
            if id_val.is_none() {
                return finish(&ctx, TcAction::Drop, &mut event);
            }

            if ip_proto.is_other() {
                return finish(&ctx, TcAction::Pass, &mut event);
            }
        }
        EthProtocol::IPv6 => {
            let iph = ctx.load::<ipv6hdr>(ETH_HDR_LEN)?;

            event6.saddr = bpf_probe_read_kernel(&iph.saddr.in6_u.u6_addr8)?;
            event6.daddr = bpf_probe_read_kernel(&iph.daddr.in6_u.u6_addr8)?;
            event6.sport = sport;
            event6.dport = dport;

            event6.protocol = iph.nexthdr;

            let mut ip_key: ContainerIP = core::mem::zeroed();

            ip_key.ipv6 = event6.daddr;

            id_val = CONTAINER_ID_FROM_IPS.get(&ip_key);
            if id_val.is_none() {
                return finish6(&ctx, TcAction::Drop, &mut event6);
            }

            if ip_proto.is_other() {
                return finish6(&ctx, TcAction::Pass, &mut event6);
            }
        }
        EthProtocol::Other(_) => return Ok(TC_ACT_OK),
    }

    let id_val = id_val.unwrap();

    let mut p_key: PortKey = core::mem::zeroed();
    p_key.container_id = bpf_probe_read_kernel(&id_val.container_id)?;
    p_key.port = dport;
    p_key.proto = ip_proto;

    let p_val = PROC_PORTS.get(&p_key);
    if p_val.is_none() {
        match eth_proto {
            EthProtocol::IP => {}
            EthProtocol::IPv6 => {}
            EthProtocol::Other(_) => {}
        }
    }

    Ok(TC_ACT_OK)
}

unsafe fn get_port(ctx: &SkBuffContext) -> Result<(u16, u16), c_long> {
    return match ip_protocol(ctx)? {
        IpProtocol::TCP => {
            let tcph = ctx.load::<tcphdr>(ETH_HDR_LEN + IP_HDR_LEN)?;
            Ok((tcph.source, tcph.dest))
        }
        IpProtocol::UDP => {
            let udph = ctx.load::<udphdr>(ETH_HDR_LEN + IP_HDR_LEN)?;
            Ok((udph.source, udph.dest))
        }
        IpProtocol::Other(_) => Err(TC_ACT_OK as c_long),
    };
}

unsafe fn finish(
    ctx: &SkBuffContext,
    action: TcAction,
    event: &mut IngressEvent,
) -> Result<i32, c_long> {
    event.action = action;
    INGRESS_EVENTS.output(ctx, event, 0);
    return Ok(match action {
        TcAction::Pass => TC_ACT_OK,
        TcAction::Drop => TC_ACT_SHOT,
    });
}

unsafe fn finish6(
    ctx: &SkBuffContext,
    action: TcAction,
    event: &mut Ingress6Event,
) -> Result<i32, c_long> {
    event.action = action;
    INGRESS6_EVENTS.output(ctx, event, 0);
    return Ok(match action {
        TcAction::Pass => TC_ACT_OK,
        TcAction::Drop => TC_ACT_SHOT,
    });
}
