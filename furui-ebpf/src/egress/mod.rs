use aya_ebpf::{bindings::TC_ACT_OK, cty::c_long, macros::classifier, programs::TcContext};
use aya_log_ebpf::warn;
use furui_common::{EthProtocol, IpProtocol};

use crate::{
    egress::{
        ipv4_icmp::ipv4_icmp, ipv4_tcp_udp::ipv4_tcp_udp, ipv6_icmp::ipv6_icmp,
        ipv6_tcp_udp::ipv6_tcp_udp,
    },
    helpers::{eth_protocol, ip_protocol},
};

mod ipv4_icmp;
mod ipv4_tcp_udp;
mod ipv6_icmp;
mod ipv6_tcp_udp;

#[classifier]
pub fn egress(ctx: TcContext) -> i32 {
    match unsafe { try_egress(&ctx) } {
        Ok(ret) => ret,
        Err(ret) => {
            if ret != 0 {
                warn!(&ctx, "egress event failed in kernel: {}", ret);
            }
            ret as i32
        }
    }
}

unsafe fn try_egress(ctx: &TcContext) -> Result<i32, c_long> {
    match (eth_protocol(ctx)?, ip_protocol(ctx)?) {
        (EthProtocol::IP, IpProtocol::TCP | IpProtocol::UDP) => ipv4_tcp_udp(ctx),
        (EthProtocol::IP, IpProtocol::ICMP) => ipv4_icmp(ctx),
        (EthProtocol::IPv6, IpProtocol::TCP | IpProtocol::UDP) => ipv6_tcp_udp(ctx),
        (EthProtocol::IPv6, IpProtocol::ICMP) => ipv6_icmp(ctx),
        _ => Ok(TC_ACT_OK),
    }
}
