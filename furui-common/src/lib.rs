#![cfg_attr(not(feature = "user"), no_std)]

#[cfg(feature = "user")]
use std::net::IpAddr;

use aya_bpf::{cty::c_char, TASK_COMM_LEN};

pub use event::*;

mod event;

#[cfg(feature = "user")]
mod helpers;

pub const CONTAINER_ID_LEN: usize = 16;
pub const IPV6_LEN: usize = 16;

#[derive(Copy, Clone)]
pub struct PortKey {
    pub container_id: [c_char; CONTAINER_ID_LEN],
    pub port: u16,
    pub proto: u8,
}

#[derive(Copy, Clone)]
pub struct PortVal {
    pub comm: [c_char; TASK_COMM_LEN],
}

#[derive(Debug, Copy, Clone)]
pub struct ContainerIP {
    pub ip: Option<u32>,
    pub ipv6: Option<[c_char; IPV6_LEN]>,
}

#[cfg(feature = "user")]
impl ContainerIP {
    pub fn new(ip: IpAddr) -> ContainerIP {
        match ip {
            IpAddr::V4(ip) => ContainerIP {
                ip: Some(ip.into()),
                ipv6: None,
            },
            IpAddr::V6(ip) => ContainerIP {
                ip: None,
                ipv6: Some(ip.octets()),
            },
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub struct ContainerID {
    pub container_id: [c_char; CONTAINER_ID_LEN],
}

#[cfg(feature = "user")]
impl ContainerID {
    pub fn new(id: [c_char; CONTAINER_ID_LEN]) -> ContainerID {
        ContainerID { container_id: id }
    }
}

#[cfg(feature = "user")]
mod user {
    use super::*;

    unsafe impl aya::Pod for ContainerIP {}
    unsafe impl aya::Pod for ContainerID {}
}
