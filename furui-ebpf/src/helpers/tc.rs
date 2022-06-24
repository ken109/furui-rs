use aya_bpf::bindings::TC_ACT_OK;
use aya_bpf::cty::c_long;
use aya_bpf::programs::SkBuffContext;

use furui_common::{EthProtocol, IpProtocol};

use crate::helpers::{ntohs, ETH_HDR_LEN};
use crate::vmlinux::{ethhdr, iphdr, ipv6hdr};

pub(crate) fn eth_protocol(ctx: &SkBuffContext) -> Result<EthProtocol, c_long> {
    let eth = ctx.load::<ethhdr>(0)?;

    Ok(EthProtocol::from_eth(ntohs(eth.h_proto)))
}

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
