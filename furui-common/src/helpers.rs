use aya_bpf::cty::c_ushort;
use libc::c_int;

pub(crate) fn family(value: c_ushort) -> &'static str {
    match value as c_int {
        libc::AF_INET => "v4",
        libc::AF_INET6 => "v6",
        _ => "",
    }
}

pub(crate) fn proto(value: u8) -> &'static str {
    match value as c_int {
        libc::IPPROTO_IP => "IP",
        libc::IPPROTO_TCP => "TCP",
        libc::IPPROTO_UDP => "UDP",
        libc::IPPROTO_ICMP => "ICMP",
        _ => "UNK",
    }
}
