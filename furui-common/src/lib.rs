#![cfg_attr(not(feature = "user"), no_std)]

use aya_bpf::{
    cty::{c_char, c_ushort},
    TASK_COMM_LEN,
};
#[cfg(feature = "user")]
use libc::c_int;

pub const CONTAINER_ID_LEN: usize = 16;

pub struct PortKey {
    pub container_id: [c_char; CONTAINER_ID_LEN],
    pub port: u16,
    pub proto: u8,
}

pub struct PortVal {
    pub comm: [c_char; TASK_COMM_LEN],
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct BindEvent {
    // Only 12 characters are in the nodename, so it's 12+termination characters,
    // but I've set it to 16 for memory alignment reasons.
    pub container_id: [c_char; CONTAINER_ID_LEN],
    pub pid: u32,
    pub comm: [c_char; TASK_COMM_LEN],
    pub family: c_ushort,
    pub lport: c_ushort,
    // // Defined at the very end for memory alignment.
    pub proto: u8,
}

#[cfg(feature = "user")]
impl BindEvent {
    pub fn family(&self) -> &'static str {
        match self.family as c_int {
            libc::AF_INET => "v4",
            libc::AF_INET6 => "v6",
            _ => "",
        }
    }

    pub fn proto(&self) -> &'static str {
        match self.proto as c_int {
            libc::IPPROTO_IP => "IP",
            libc::IPPROTO_TCP => "TCP",
            libc::IPPROTO_UDP => "UDP",
            libc::IPPROTO_ICMP => "ICMP",
            _ => "UNK",
        }
    }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct ConnectEvent {
    // Only 12 characters are in the nodename, so it's 12+termination characters,
    // but I've set it to 16 for memory alignment reasons.
    pub container_id: [c_char; CONTAINER_ID_LEN],
    pub pid: u32,
    pub comm: [c_char; TASK_COMM_LEN],
}

#[cfg(feature = "user")]
mod user {
    use super::*;

    unsafe impl aya::Pod for BindEvent {}
}
