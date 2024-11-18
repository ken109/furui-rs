use aya_ebpf::bindings::{TC_ACT_OK, TC_ACT_SHOT};
use aya_ebpf::cty::c_long;
use aya_ebpf::helpers::bpf_probe_read_kernel;
use aya_ebpf::macros::map;
use aya_ebpf::maps::PerfEventArray;
use aya_ebpf::programs::TcContext;

use furui_common::{ContainerIP, Ingress6Event, PolicyKey, PortKey, TcAction};

use crate::helpers::{eth_protocol, get_port, ip_protocol, ETH_HDR_LEN};
use crate::vmlinux::ipv6hdr;
use crate::{CONTAINER_ID_FROM_IPS, POLICY_LIST, PROC_PORTS};

#[map]
static mut INGRESS6_EVENTS: PerfEventArray<Ingress6Event> =
    PerfEventArray::<Ingress6Event>::new(0);

pub(crate) unsafe fn ipv6_tcp_udp(ctx: &TcContext) -> Result<i32, c_long> {
    let mut event: Ingress6Event = core::mem::zeroed();

    let iph = ctx.load::<ipv6hdr>(ETH_HDR_LEN)?;

    event.saddr =
        bpf_probe_read_kernel(&iph.__bindgen_anon_1.__bindgen_anon_1.saddr.in6_u.u6_addr8)?;
    event.daddr =
        bpf_probe_read_kernel(&iph.__bindgen_anon_1.__bindgen_anon_1.daddr.in6_u.u6_addr8)?;
    (event.sport, event.dport) = get_port(ctx)?;

    event.family = eth_protocol(ctx)?;
    event.protocol = ip_protocol(ctx)?;

    let mut ip_key: ContainerIP = core::mem::zeroed();

    ip_key.ipv6 = event.daddr;

    let cid_val = CONTAINER_ID_FROM_IPS.get(&ip_key);
    if cid_val.is_none() {
        return Ok(TC_ACT_SHOT);
    }

    event.container_id = bpf_probe_read_kernel(&cid_val.unwrap().container_id)?;

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

    if event.search_key(&mut policy_key, |policy_key| {
        POLICY_LIST.get(&policy_key).is_some()
    }) {
        return finish(ctx, TcAction::Pass, &mut event);
    }

    finish(ctx, TcAction::Drop, &mut event)
}

unsafe fn finish(
    ctx: &TcContext,
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
