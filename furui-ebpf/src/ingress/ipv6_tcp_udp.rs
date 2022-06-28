use aya_bpf::bindings::{TC_ACT_OK, TC_ACT_SHOT};
use aya_bpf::cty::c_long;
use aya_bpf::helpers::bpf_probe_read_kernel;
use aya_bpf::macros::map;
use aya_bpf::maps::PerfEventArray;
use aya_bpf::programs::SkBuffContext;

use furui_common::{
    ContainerIP, Ingress6Event, IpProtocol, PolicyKey, PortKey, TcAction, IPV6_LEN,
};

use crate::helpers::{eth_protocol, get_port, ip_protocol, ETH_HDR_LEN};
use crate::vmlinux::ipv6hdr;
use crate::{CONTAINER_ID_FROM_IPS, POLICY_LIST, PROC_PORTS};

#[map]
static mut INGRESS6_EVENTS: PerfEventArray<Ingress6Event> =
    PerfEventArray::<Ingress6Event>::with_max_entries(1024, 0);

pub(crate) unsafe fn ipv6_tcp_udp(ctx: &SkBuffContext) -> Result<i32, c_long> {
    let mut event: Ingress6Event = core::mem::zeroed();

    let iph = ctx.load::<ipv6hdr>(ETH_HDR_LEN)?;

    event.saddr = bpf_probe_read_kernel(&iph.saddr.in6_u.u6_addr8)?;
    event.daddr = bpf_probe_read_kernel(&iph.daddr.in6_u.u6_addr8)?;
    (event.sport, event.dport) = get_port(ctx)?;

    event.family = eth_protocol(ctx)?;
    event.protocol = ip_protocol(ctx)?;

    let mut ip_key: ContainerIP = core::mem::zeroed();

    ip_key.ipv6 = event.daddr;

    let cid_val = CONTAINER_ID_FROM_IPS.get(&ip_key);
    if cid_val.is_none() {
        return finish(ctx, TcAction::Drop, &mut event);
    }

    event.container_id = bpf_probe_read_kernel(&cid_val.unwrap().container_id)?;

    if event.protocol.is_other() {
        return finish(ctx, TcAction::Pass, &mut event);
    }

    // port
    let mut port_key: PortKey = core::mem::zeroed();
    port_key.container_id = event.container_id;
    port_key.port = event.dport;
    port_key.proto = event.protocol;

    let port_val = PROC_PORTS.get(&port_key);
    if port_val.is_none() {
        return finish(ctx, TcAction::Drop, &mut event);
    }

    let port_val = port_val.unwrap();

    let mut policy_key: PolicyKey = core::mem::zeroed();

    // If nothing is specified in the policy except the container name and
    // executable name, allow all communication to that process.
    policy_key.container_id = event.container_id;
    policy_key.comm = bpf_probe_read_kernel(&port_val.comm)?;
    let policy_val = POLICY_LIST.get(&policy_key);
    if policy_val.is_some() {
        return finish(ctx, TcAction::Pass, &mut event);
    }

    event.comm = bpf_probe_read_kernel(&port_val.comm)?;

    // section
    policy_key.protocol = event.protocol;
    policy_key.local_port = 0;
    policy_key.remote_ipv6 = [0; IPV6_LEN];
    policy_key.remote_port = 0;
    let policy_val = POLICY_LIST.get(&policy_key);
    if policy_val.is_some() {
        return finish(ctx, TcAction::Pass, &mut event);
    }

    policy_key.local_port = event.dport;
    let policy_val = POLICY_LIST.get(&policy_key);
    if policy_val.is_some() {
        return finish(ctx, TcAction::Pass, &mut event);
    }

    policy_key.remote_ipv6 = event.saddr;
    let policy_val = POLICY_LIST.get(&policy_key);
    if policy_val.is_some() {
        return finish(ctx, TcAction::Pass, &mut event);
    }

    policy_key.remote_port = event.sport;
    let policy_val = POLICY_LIST.get(&policy_key);
    if policy_val.is_some() {
        return finish(ctx, TcAction::Pass, &mut event);
    }

    // section
    policy_key.protocol = IpProtocol::default();
    policy_key.local_port = event.dport;
    policy_key.remote_ipv6 = [0; IPV6_LEN];
    policy_key.remote_port = 0;
    let policy_val = POLICY_LIST.get(&policy_key);
    if policy_val.is_some() {
        return finish(ctx, TcAction::Pass, &mut event);
    }

    policy_key.remote_ipv6 = event.saddr;
    let policy_val = POLICY_LIST.get(&policy_key);
    if policy_val.is_some() {
        return finish(ctx, TcAction::Pass, &mut event);
    }

    policy_key.remote_port = event.sport;
    let policy_val = POLICY_LIST.get(&policy_key);
    if policy_val.is_some() {
        return finish(ctx, TcAction::Pass, &mut event);
    }

    // section
    policy_key.protocol = IpProtocol::default();
    policy_key.local_port = 0;
    policy_key.remote_ipv6 = event.saddr;
    policy_key.remote_port = 0;
    let policy_val = POLICY_LIST.get(&policy_key);
    if policy_val.is_some() {
        return finish(ctx, TcAction::Pass, &mut event);
    }

    policy_key.remote_port = event.sport;
    let policy_val = POLICY_LIST.get(&policy_key);
    if policy_val.is_some() {
        return finish(ctx, TcAction::Pass, &mut event);
    }

    // section
    policy_key.protocol = event.protocol;
    policy_key.local_port = 0;
    policy_key.remote_ipv6 = event.saddr;
    policy_key.remote_port = 0;
    let policy_val = POLICY_LIST.get(&policy_key);
    if policy_val.is_some() {
        return finish(ctx, TcAction::Pass, &mut event);
    }

    policy_key.remote_port = event.sport;
    let policy_val = POLICY_LIST.get(&policy_key);
    if policy_val.is_some() {
        return finish(ctx, TcAction::Pass, &mut event);
    }

    // reverse section
    policy_key.protocol = IpProtocol::default();
    policy_key.local_port = 0;
    policy_key.remote_ipv6 = [0; IPV6_LEN];
    policy_key.remote_port = event.sport;
    let policy_val = POLICY_LIST.get(&policy_key);
    if policy_val.is_some() {
        return finish(ctx, TcAction::Pass, &mut event);
    }

    policy_key.local_port = event.dport;
    let policy_val = POLICY_LIST.get(&policy_key);
    if policy_val.is_some() {
        return finish(ctx, TcAction::Pass, &mut event);
    }

    policy_key.protocol = event.protocol;
    let policy_val = POLICY_LIST.get(&policy_key);
    if policy_val.is_some() {
        return finish(ctx, TcAction::Pass, &mut event);
    }

    // reverse section
    policy_key.protocol = event.protocol;
    policy_key.local_port = 0;
    policy_key.remote_ipv6 = [0; IPV6_LEN];
    policy_key.remote_port = event.sport;
    let policy_val = POLICY_LIST.get(&policy_key);
    if policy_val.is_some() {
        return finish(ctx, TcAction::Pass, &mut event);
    }

    finish(ctx, TcAction::Drop, &mut event)
}

unsafe fn finish(
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
