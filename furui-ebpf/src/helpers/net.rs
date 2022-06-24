use aya_bpf::cty::c_ushort;

use crate::vmlinux::{ethhdr, iphdr};

pub(crate) static AF_INET: c_ushort = 2;
pub(crate) static AF_INET6: c_ushort = 10;

pub(crate) const ETH_HDR_LEN: usize = core::mem::size_of::<ethhdr>();
pub(crate) const IP_HDR_LEN: usize = core::mem::size_of::<iphdr>();

pub(crate) fn ntohs(value: u16) -> u16 {
    u16::from_be(value)
}

pub(crate) fn ntohl(value: u32) -> u32 {
    u32::from_be(value)
}
