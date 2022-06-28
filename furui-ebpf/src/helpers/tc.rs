use aya_bpf::bindings::TC_ACT_OK;
use aya_bpf::cty::c_long;
use aya_bpf::programs::SkBuffContext;

use furui_common::{EthProtocol, IpProtocol};

use crate::helpers::{ntohs, ETH_HDR_LEN, IPV6_HDR_LEN, IP_HDR_LEN};
use crate::vmlinux::{ethhdr, iphdr, ipv6hdr, tcphdr, udphdr};

#[inline]
pub(crate) fn eth_protocol(ctx: &SkBuffContext) -> Result<EthProtocol, c_long> {
    let eth = ctx.load::<ethhdr>(0)?;

    Ok(EthProtocol::from_eth(ntohs(eth.h_proto)))
}

#[inline]
pub(crate) fn ip_protocol(ctx: &SkBuffContext) -> Result<IpProtocol, c_long> {
    match eth_protocol(ctx)? {
        EthProtocol::IP => {
            let iph = ctx.load::<iphdr>(ETH_HDR_LEN)?;

            Ok(IpProtocol::new(iph.protocol))
        }
        EthProtocol::IPv6 => {
            let iph = ctx.load::<ipv6hdr>(ETH_HDR_LEN)?;

            Ok(IpProtocol::new(iph.nexthdr))
        }
        EthProtocol::Other => Err(TC_ACT_OK as c_long),
    }
}

pub(crate) unsafe fn get_port(ctx: &SkBuffContext) -> Result<(u16, u16), c_long> {
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
        _ => Err(TC_ACT_OK as c_long),
    };
}
