#[cfg(feature = "user")]
use std::net::IpAddr;

use aya_bpf::cty::c_char;
use aya_bpf::TASK_COMM_LEN;

use crate::{IpProtocol, CONTAINER_ID_LEN, IPV6_LEN};

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct PolicyKey {
    pub container_id: [c_char; CONTAINER_ID_LEN],
    pub comm: [c_char; TASK_COMM_LEN],
    pub remote_ip: u32,
    pub remote_ipv6: [c_char; IPV6_LEN],
    pub local_port: u16,
    pub remote_port: u16,
    pub protocol: IpProtocol,
}

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct PolicyValue {
    pub comm: [c_char; TASK_COMM_LEN],
    pub remote_ip: u32,
    pub remote_ipv6: [c_char; IPV6_LEN],
    pub local_port: u16,
    pub remote_port: u16,
    pub protocol: IpProtocol,
}

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct IcmpPolicyKey {
    pub container_id: [c_char; CONTAINER_ID_LEN],
    pub version: u8,
    pub icmp_type: u8,
    pub code: u8,
    pub remote_ip: u32,
    pub remote_ipv6: [c_char; IPV6_LEN],
}

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct IcmpPolicyValue {
    pub version: u8,
    pub icmp_type: u8,
    pub code: u8,
    pub remote_ip: u32,
    pub remote_ipv6: [c_char; IPV6_LEN],
}

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct PortKey {
    pub container_id: [c_char; CONTAINER_ID_LEN],
    pub port: u16,
    pub proto: IpProtocol,
}

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct PortVal {
    pub comm: [c_char; TASK_COMM_LEN],
}

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct ContainerIP {
    pub ip: u32,
    pub ipv6: [c_char; IPV6_LEN],
}

#[cfg(feature = "user")]
impl ContainerIP {
    pub fn new(ip: IpAddr) -> ContainerIP {
        match ip {
            IpAddr::V4(ip) => ContainerIP {
                ip: ip.into(),
                ipv6: Default::default(),
            },
            IpAddr::V6(ip) => ContainerIP {
                ip: Default::default(),
                ipv6: ip.octets(),
            },
        }
    }
}

#[derive(Debug, Copy, Clone)]
#[repr(C)]
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

    unsafe impl aya::Pod for PolicyKey {}
    unsafe impl aya::Pod for PolicyValue {}
    unsafe impl aya::Pod for IcmpPolicyKey {}
    unsafe impl aya::Pod for IcmpPolicyValue {}
    unsafe impl aya::Pod for PortKey {}
    unsafe impl aya::Pod for PortVal {}
    unsafe impl aya::Pod for ContainerIP {}
    unsafe impl aya::Pod for ContainerID {}
}
