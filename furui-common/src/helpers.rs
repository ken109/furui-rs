use std::convert::TryInto;

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
