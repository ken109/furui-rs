use aya_bpf::bindings::{TC_ACT_OK, TC_ACT_SHOT};
use aya_bpf::cty::c_long;
use aya_bpf::helpers::bpf_probe_read_kernel;
use aya_bpf::maps::PerfEventArray;
use aya_bpf::{
    macros::{classifier, map},
    programs::SkBuffContext,
};
use aya_log_ebpf::warn;

use furui_common::{
    ContainerID, ContainerIP, EthProtocol, Ingress6Event, IngressEvent, IpProtocol, PolicyKey,
    PortKey, TcAction, IPV6_LEN,
};

use crate::helpers::{
    eth_protocol, ip_protocol, ntohl, ntohs, ETH_HDR_LEN, IPV6_HDR_LEN, IP_HDR_LEN,
};
use crate::vmlinux::{iphdr, ipv6hdr, tcphdr, udphdr};
use crate::{CONTAINER_ID_FROM_IPS, POLICY_LIST, PROC_PORTS};

#[map]
pub(crate) static mut INGRESS_EVENTS: PerfEventArray<IngressEvent> =
    PerfEventArray::<IngressEvent>::with_max_entries(1024, 0);

#[map]
pub(crate) static mut INGRESS6_EVENTS: PerfEventArray<Ingress6Event> =
    PerfEventArray::<Ingress6Event>::with_max_entries(1024, 0);

#[classifier(name = "ingress")]
pub fn ingress(ctx: SkBuffContext) -> i32 {
    match unsafe { try_ingress(&ctx) } {
        Ok(ret) => ret,
        Err(ret) => {
            if ret != 0 {
                warn!(&ctx, "ingress event failed in kernel: {}", ret);
            }
            ret as i32
        }
    }
}

unsafe fn try_ingress(ctx: &SkBuffContext) -> Result<i32, c_long> {
    let mut event: IngressEvent = core::mem::zeroed();
    let mut event6: Ingress6Event = core::mem::zeroed();

    let id_val: Option<&ContainerID>;

    let (sport, dport) = get_port(ctx)?;
    let eth_proto = eth_protocol(ctx)?;
    let ip_proto = ip_protocol(ctx)?;

    match eth_proto {
        EthProtocol::IP => {
            let iph = ctx.load::<iphdr>(ETH_HDR_LEN)?;

            event.saddr = ntohl(iph.saddr);
            event.daddr = ntohl(iph.daddr);
            event.sport = sport;
            event.dport = dport;

            event.family = eth_proto;
            event.protocol = ip_proto;

            let mut ip_key: ContainerIP = core::mem::zeroed();

            ip_key.ip = event.daddr;

            id_val = CONTAINER_ID_FROM_IPS.get(&ip_key);
            if id_val.is_none() {
                return finish4(ctx, TcAction::Drop, &mut event);
            }

            event.container_id = bpf_probe_read_kernel(&id_val.unwrap().container_id)?;

            if ip_proto.is_other() {
                return finish4(ctx, TcAction::Pass, &mut event);
            }
        }
        EthProtocol::IPv6 => {
            let iph = ctx.load::<ipv6hdr>(ETH_HDR_LEN)?;

            event6.saddr = bpf_probe_read_kernel(&iph.saddr.in6_u.u6_addr8)?;
            event6.daddr = bpf_probe_read_kernel(&iph.daddr.in6_u.u6_addr8)?;
            event6.sport = sport;
            event6.dport = dport;

            event6.family = eth_proto;
            event6.protocol = ip_proto;

            let mut ip_key: ContainerIP = core::mem::zeroed();

            ip_key.ipv6 = event6.daddr;

            id_val = CONTAINER_ID_FROM_IPS.get(&ip_key);
            if id_val.is_none() {
                return finish6(ctx, TcAction::Drop, &mut event6);
            }

            event6.container_id = bpf_probe_read_kernel(&id_val.unwrap().container_id)?;

            if ip_proto.is_other() {
                return finish6(ctx, TcAction::Pass, &mut event6);
            }
        }
        EthProtocol::Other => return Ok(TC_ACT_OK),
    }

    let cid_val = id_val.unwrap();

    // port
    let mut port_key: PortKey = core::mem::zeroed();
    port_key.container_id = bpf_probe_read_kernel(&cid_val.container_id)?;
    port_key.port = dport;
    port_key.proto = ip_proto;

    let port_val = PROC_PORTS.get(&port_key);
    if port_val.is_none() {
        return match eth_proto {
            EthProtocol::IP => finish4(ctx, TcAction::Drop, &mut event),
            EthProtocol::IPv6 => finish6(ctx, TcAction::Drop, &mut event6),
            EthProtocol::Other => Ok(TC_ACT_OK),
        };
    }

    let port_val = port_val.unwrap();

    let mut policy_key: PolicyKey = core::mem::zeroed();

    // If nothing is specified in the policy except the container name and
    // executable name, allow all communication to that process.
    policy_key.container_id = bpf_probe_read_kernel(&cid_val.container_id)?;
    policy_key.comm = bpf_probe_read_kernel(&port_val.comm)?;
    let policy_val = POLICY_LIST.get(&policy_key);
    if policy_val.is_some() {
        return finish(ctx, TcAction::Pass, &mut event, &mut event6);
    }

    return match eth_proto {
        EthProtocol::IP => {
            event.comm = bpf_probe_read_kernel(&port_val.comm)?;

            // section
            policy_key.protocol = event.protocol;
            policy_key.local_port = 0;
            policy_key.remote_ip = 0;
            policy_key.remote_port = 0;
            let policy_val = POLICY_LIST.get(&policy_key);
            if policy_val.is_some() {
                return finish4(ctx, TcAction::Pass, &mut event);
            }

            policy_key.local_port = event.dport;
            let policy_val = POLICY_LIST.get(&policy_key);
            if policy_val.is_some() {
                return finish4(ctx, TcAction::Pass, &mut event);
            }

            policy_key.remote_ip = event.saddr;
            let policy_val = POLICY_LIST.get(&policy_key);
            if policy_val.is_some() {
                return finish4(ctx, TcAction::Pass, &mut event);
            }

            policy_key.remote_port = event.sport;
            let policy_val = POLICY_LIST.get(&policy_key);
            if policy_val.is_some() {
                return finish4(ctx, TcAction::Pass, &mut event);
            }

            // section
            policy_key.protocol = IpProtocol::default();
            policy_key.local_port = event.dport;
            policy_key.remote_ip = 0;
            policy_key.remote_port = 0;
            let policy_val = POLICY_LIST.get(&policy_key);
            if policy_val.is_some() {
                return finish4(ctx, TcAction::Pass, &mut event);
            }

            policy_key.remote_ip = event.saddr;
            let policy_val = POLICY_LIST.get(&policy_key);
            if policy_val.is_some() {
                return finish4(ctx, TcAction::Pass, &mut event);
            }

            policy_key.remote_port = event.sport;
            let policy_val = POLICY_LIST.get(&policy_key);
            if policy_val.is_some() {
                return finish4(ctx, TcAction::Pass, &mut event);
            }

            // section
            policy_key.protocol = IpProtocol::default();
            policy_key.local_port = 0;
            policy_key.remote_ip = event.saddr;
            policy_key.remote_port = 0;
            let policy_val = POLICY_LIST.get(&policy_key);
            if policy_val.is_some() {
                return finish4(ctx, TcAction::Pass, &mut event);
            }

            policy_key.remote_port = event.sport;
            let policy_val = POLICY_LIST.get(&policy_key);
            if policy_val.is_some() {
                return finish4(ctx, TcAction::Pass, &mut event);
            }

            // section
            policy_key.protocol = event.protocol;
            policy_key.local_port = 0;
            policy_key.remote_ip = event.saddr;
            policy_key.remote_port = 0;
            let policy_val = POLICY_LIST.get(&policy_key);
            if policy_val.is_some() {
                return finish4(ctx, TcAction::Pass, &mut event);
            }

            policy_key.remote_port = event.sport;
            let policy_val = POLICY_LIST.get(&policy_key);
            if policy_val.is_some() {
                return finish4(ctx, TcAction::Pass, &mut event);
            }

            // reverse section
            policy_key.protocol = IpProtocol::default();
            policy_key.local_port = 0;
            policy_key.remote_ip = 0;
            policy_key.remote_port = event.sport;
            let policy_val = POLICY_LIST.get(&policy_key);
            if policy_val.is_some() {
                return finish4(ctx, TcAction::Pass, &mut event);
            }

            policy_key.local_port = event.dport;
            let policy_val = POLICY_LIST.get(&policy_key);
            if policy_val.is_some() {
                return finish4(ctx, TcAction::Pass, &mut event);
            }

            policy_key.protocol = event.protocol;
            let policy_val = POLICY_LIST.get(&policy_key);
            if policy_val.is_some() {
                return finish4(ctx, TcAction::Pass, &mut event);
            }

            // reverse section
            policy_key.protocol = event.protocol;
            policy_key.local_port = 0;
            policy_key.remote_ip = 0;
            policy_key.remote_port = event.sport;
            let policy_val = POLICY_LIST.get(&policy_key);
            if policy_val.is_some() {
                return finish4(ctx, TcAction::Pass, &mut event);
            }

            finish4(ctx, TcAction::Drop, &mut event)
        }
        EthProtocol::IPv6 => {
            event6.comm = bpf_probe_read_kernel(&port_val.comm)?;

            // section
            policy_key.protocol = event6.protocol;
            policy_key.local_port = 0;
            policy_key.remote_ipv6 = [0; IPV6_LEN];
            policy_key.remote_port = 0;
            let policy_val = POLICY_LIST.get(&policy_key);
            if policy_val.is_some() {
                return finish6(ctx, TcAction::Pass, &mut event6);
            }

            policy_key.local_port = event6.dport;
            let policy_val = POLICY_LIST.get(&policy_key);
            if policy_val.is_some() {
                return finish6(ctx, TcAction::Pass, &mut event6);
            }

            policy_key.remote_ipv6 = event6.saddr;
            let policy_val = POLICY_LIST.get(&policy_key);
            if policy_val.is_some() {
                return finish6(ctx, TcAction::Pass, &mut event6);
            }

            policy_key.remote_port = event6.sport;
            let policy_val = POLICY_LIST.get(&policy_key);
            if policy_val.is_some() {
                return finish6(ctx, TcAction::Pass, &mut event6);
            }

            // section
            policy_key.protocol = IpProtocol::default();
            policy_key.local_port = event6.dport;
            policy_key.remote_ipv6 = [0; IPV6_LEN];
            policy_key.remote_port = 0;
            let policy_val = POLICY_LIST.get(&policy_key);
            if policy_val.is_some() {
                return finish6(ctx, TcAction::Pass, &mut event6);
            }

            policy_key.remote_ipv6 = event6.saddr;
            let policy_val = POLICY_LIST.get(&policy_key);
            if policy_val.is_some() {
                return finish6(ctx, TcAction::Pass, &mut event6);
            }

            policy_key.remote_port = event6.sport;
            let policy_val = POLICY_LIST.get(&policy_key);
            if policy_val.is_some() {
                return finish6(ctx, TcAction::Pass, &mut event6);
            }

            // section
            policy_key.protocol = IpProtocol::default();
            policy_key.local_port = 0;
            policy_key.remote_ipv6 = event6.saddr;
            policy_key.remote_port = 0;
            let policy_val = POLICY_LIST.get(&policy_key);
            if policy_val.is_some() {
                return finish6(ctx, TcAction::Pass, &mut event6);
            }

            policy_key.remote_port = event6.sport;
            let policy_val = POLICY_LIST.get(&policy_key);
            if policy_val.is_some() {
                return finish6(ctx, TcAction::Pass, &mut event6);
            }

            // section
            policy_key.protocol = event6.protocol;
            policy_key.local_port = 0;
            policy_key.remote_ipv6 = event6.saddr;
            policy_key.remote_port = 0;
            let policy_val = POLICY_LIST.get(&policy_key);
            if policy_val.is_some() {
                return finish6(ctx, TcAction::Pass, &mut event6);
            }

            policy_key.remote_port = event6.sport;
            let policy_val = POLICY_LIST.get(&policy_key);
            if policy_val.is_some() {
                return finish6(ctx, TcAction::Pass, &mut event6);
            }

            // reverse section
            policy_key.protocol = IpProtocol::default();
            policy_key.local_port = 0;
            policy_key.remote_ipv6 = [0; IPV6_LEN];
            policy_key.remote_port = event6.sport;
            let policy_val = POLICY_LIST.get(&policy_key);
            if policy_val.is_some() {
                return finish6(ctx, TcAction::Pass, &mut event6);
            }

            policy_key.local_port = event6.dport;
            let policy_val = POLICY_LIST.get(&policy_key);
            if policy_val.is_some() {
                return finish6(ctx, TcAction::Pass, &mut event6);
            }

            policy_key.protocol = event6.protocol;
            let policy_val = POLICY_LIST.get(&policy_key);
            if policy_val.is_some() {
                return finish6(ctx, TcAction::Pass, &mut event6);
            }

            // reverse section
            policy_key.protocol = event6.protocol;
            policy_key.local_port = 0;
            policy_key.remote_ipv6 = [0; IPV6_LEN];
            policy_key.remote_port = event6.sport;
            let policy_val = POLICY_LIST.get(&policy_key);
            if policy_val.is_some() {
                return finish6(ctx, TcAction::Pass, &mut event6);
            }

            finish6(ctx, TcAction::Drop, &mut event6)
        }
        EthProtocol::Other => Ok(TC_ACT_OK),
    };
}

unsafe fn get_port(ctx: &SkBuffContext) -> Result<(u16, u16), c_long> {
    let ip_hdr_len = match eth_protocol(ctx)? {
        EthProtocol::IP => IP_HDR_LEN,
        EthProtocol::IPv6 => IPV6_HDR_LEN,
        EthProtocol::Other => return Err(TC_ACT_OK as c_long),
    };

    return match ip_protocol(ctx)? {
        IpProtocol::TCP => {
            let tcph = ctx.load::<tcphdr>(ETH_HDR_LEN + ip_hdr_len)?;
            Ok((ntohs(tcph.source), ntohs(tcph.dest)))
        }
        IpProtocol::UDP => {
            let udph = ctx.load::<udphdr>(ETH_HDR_LEN + ip_hdr_len)?;
            Ok((ntohs(udph.source), ntohs(udph.dest)))
        }
        IpProtocol::Default | IpProtocol::Other => Err(TC_ACT_OK as c_long),
    };
}

unsafe fn finish(
    ctx: &SkBuffContext,
    action: TcAction,
    event: &mut IngressEvent,
    event6: &mut Ingress6Event,
) -> Result<i32, c_long> {
    match eth_protocol(ctx)? {
        EthProtocol::IP => finish4(ctx, action, event),
        EthProtocol::IPv6 => finish6(ctx, action, event6),
        EthProtocol::Other => Ok(TC_ACT_OK),
    }
}

unsafe fn finish4(
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
