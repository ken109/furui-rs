use aya_bpf::cty::c_ushort;
use libc::c_int;
use std::convert::TryInto;

pub(crate) fn family_value_to_str(value: c_ushort) -> &'static str {
    match value as c_int {
        libc::AF_INET => "v4",
        libc::AF_INET6 => "v6",
        _ => "",
    }
}

pub fn protocol_str_to_value(src: &str) -> u8 {
    match src {
        "ip" => libc::IPPROTO_IP,
        "tcp" | "tcp6" => libc::IPPROTO_TCP,
        "udp" | "udp6" => libc::IPPROTO_UDP,
        &_ => 255,
    }
    .try_into()
    .unwrap()
}
