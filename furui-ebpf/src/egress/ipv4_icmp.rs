use aya_bpf::bindings::{TC_ACT_OK, TC_ACT_SHOT};
use aya_bpf::cty::c_long;
use aya_bpf::helpers::bpf_probe_read_kernel;
use aya_bpf::macros::map;
use aya_bpf::maps::PerfEventArray;
use aya_bpf::programs::TcContext;

use furui_common::{ContainerIP, EgressIcmpEvent, IcmpPolicyKey, IcmpVersion, TcAction};

use crate::helpers::{eth_protocol, ip_protocol, ntohl, ETH_HDR_LEN, IP_HDR_LEN};
use crate::vmlinux::{icmphdr, iphdr};
use crate::{CONTAINER_ID_FROM_IPS, ICMP_POLICY_LIST};

#[map]
static mut EGRESS_ICMP_EVENTS: PerfEventArray<EgressIcmpEvent> =
    PerfEventArray::<EgressIcmpEvent>::with_max_entries(1024, 0);

pub(crate) unsafe fn ipv4_icmp(ctx: &TcContext) -> Result<i32, c_long> {
    let mut event: EgressIcmpEvent = core::mem::zeroed();

    let iph = ctx.load::<iphdr>(ETH_HDR_LEN)?;

    event.saddr = ntohl(iph.__bindgen_anon_1.__bindgen_anon_1.saddr);
    event.daddr = ntohl(iph.__bindgen_anon_1.__bindgen_anon_1.daddr);

    event.family = eth_protocol(ctx)?;
    event.protocol = ip_protocol(ctx)?;

    let icmph = ctx.load::<icmphdr>(ETH_HDR_LEN + IP_HDR_LEN)?;
    event.version = IcmpVersion::V4;
    event.type_ = icmph.type_;
    event.code = icmph.code;

    let mut ip_key: ContainerIP = core::mem::zeroed();
    ip_key.ip = event.saddr;

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
    ctx: &TcContext,
    action: TcAction,
    event: &mut EgressIcmpEvent,
) -> Result<i32, c_long> {
    event.action = action;
    EGRESS_ICMP_EVENTS.output(ctx, event, 0);
    return Ok(match action {
        TcAction::Pass => TC_ACT_OK,
        TcAction::Drop => TC_ACT_SHOT,
    });
}
