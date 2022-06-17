use aya_bpf::cty::c_ushort;

pub(crate) static AF_INET: c_ushort = 2;
pub(crate) static AF_INET6: c_ushort = 10;

pub(crate) fn ntohs(value: u16) -> u16 {
    u16::from_be(value)
}
