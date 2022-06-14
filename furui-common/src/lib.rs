#![no_std]

use aya_bpf::{cty::c_char, TASK_COMM_LEN};

pub struct PortKey {
    pub container_id: [c_char; 16],
    pub port: u16,
    pub proto: u8,
}

pub struct PortVal {
    pub comm: [c_char; TASK_COMM_LEN],
}

#[repr(C)]
pub struct BindEvent {
    // Only 12 characters are in the nodename, so it's 12+termination characters,
    // but I've set it to 16 for memory alignment reasons.
    pub container_id: [c_char; 16],
    pub pid: u32,
    pub comm: [c_char; TASK_COMM_LEN],
    // pub family: u16,
    // pub lport: u16,
    // // // Defined at the very end for memory alignment.
    // pub proto: u8,
}

#[repr(C)]
pub struct ConnectEvent {
    // Only 12 characters are in the nodename, so it's 12+termination characters,
    // but I've set it to 16 for memory alignment reasons.
    // pub container_id: [c_char; 16],
    pub pid: u32,
    pub comm: [c_char; TASK_COMM_LEN],
}
