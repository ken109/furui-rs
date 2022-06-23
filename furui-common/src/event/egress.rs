use aya_bpf::cty::c_char;
use aya_bpf::TASK_COMM_LEN;

use crate::IPV6_LEN;

#[derive(Copy, Clone)]
#[repr(C)]
pub struct EgressEvent {
    saddr: u32,
    daddr: u32,
    sport: u32,
    dport: u32,
    proto: u32,
    action: u32,
    comm: [c_char; TASK_COMM_LEN],
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct Egress6Event {
    saddr: [c_char; IPV6_LEN],
    daddr: [c_char; IPV6_LEN],
    sport: u32,
    dport: u32,
    proto: u32,
    action: u32,
    comm: [c_char; TASK_COMM_LEN],
}
