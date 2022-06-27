use crate::vmlinux::{ethhdr, iphdr, ipv6hdr};

pub(crate) const ETH_HDR_LEN: usize = core::mem::size_of::<ethhdr>();
pub(crate) const IP_HDR_LEN: usize = core::mem::size_of::<iphdr>();
pub(crate) const IPV6_HDR_LEN: usize = core::mem::size_of::<ipv6hdr>();

#[inline]
pub(crate) fn ntohs(value: u16) -> u16 {
    u16::from_be(value)
}

#[inline]
pub(crate) fn ntohl(value: u32) -> u32 {
    u32::from_be(value)
}
