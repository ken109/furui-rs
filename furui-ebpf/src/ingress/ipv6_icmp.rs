use aya_bpf::bindings::{TC_ACT_OK, TC_ACT_SHOT};
use aya_bpf::cty::c_long;
use aya_bpf::helpers::bpf_probe_read_kernel;
use aya_bpf::macros::map;
use aya_bpf::maps::PerfEventArray;
use aya_bpf::programs::SkBuffContext;

use furui_common::{ContainerIP, IcmpPolicyKey, IcmpVersion, Ingress6IcmpEvent, TcAction};

use crate::helpers::{
    eth_protocol, ip_protocol, ETH_HDR_LEN, IPV6_HDR_LEN, NEIGHBOR_ADVERTISEMENT,
    NEIGHBOR_SOLICITAION,
};
use crate::vmlinux::{icmphdr, ipv6hdr};
use crate::{CONTAINER_ID_FROM_IPS, ICMP_POLICY_LIST};

#[map]
static mut INGRESS6_ICMP_EVENTS: PerfEventArray<Ingress6IcmpEvent> =
    PerfEventArray::<Ingress6IcmpEvent>::with_max_entries(1024, 0);

pub(crate) unsafe fn ipv6_icmp(ctx: &SkBuffContext) -> Result<i32, c_long> {
    let mut event: Ingress6IcmpEvent = core::mem::zeroed();

    let iph = ctx.load::<ipv6hdr>(ETH_HDR_LEN)?;

    event.saddr = bpf_probe_read_kernel(&iph.saddr.in6_u.u6_addr8)?;
    event.daddr = bpf_probe_read_kernel(&iph.daddr.in6_u.u6_addr8)?;

    event.family = eth_protocol(ctx)?;
    event.protocol = ip_protocol(ctx)?;

    let icmph = ctx.load::<icmphdr>(ETH_HDR_LEN + IPV6_HDR_LEN)?;
    event.version = IcmpVersion::V6;
    event.type_ = icmph.type_;
    event.code = icmph.code;

    if event.type_ == NEIGHBOR_SOLICITAION || event.type_ == NEIGHBOR_ADVERTISEMENT {
        return Ok(TC_ACT_OK);
    }

    let mut ip_key: ContainerIP = core::mem::zeroed();
    ip_key.ipv6 = event.daddr;

    let cid_val = CONTAINER_ID_FROM_IPS.get(&ip_key);
    if cid_val.is_none() {
        return Ok(TC_ACT_SHOT);
    }

    event.container_id = bpf_probe_read_kernel(&cid_val.unwrap().container_id)?;

    let mut policy_key: IcmpPolicyKey = core::mem::zeroed();

    policy_key.container_id = event.container_id;
    policy_key.version = event.version;

    if event.search_key(&mut policy_key, |policy_key| {
        ICMP_POLICY_LIST.get(&policy_key).is_some()
    }) {
        return finish(ctx, TcAction::Pass, &mut event);
    }

    finish(ctx, TcAction::Drop, &mut event)
}

unsafe fn finish(
    ctx: &SkBuffContext,
    action: TcAction,
    event: &mut Ingress6IcmpEvent,
) -> Result<i32, c_long> {
    event.action = action;
    INGRESS6_ICMP_EVENTS.output(ctx, event, 0);
    return Ok(match action {
        TcAction::Pass => TC_ACT_OK,
        TcAction::Drop => TC_ACT_SHOT,
    });
}
