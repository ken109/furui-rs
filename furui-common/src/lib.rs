#![cfg_attr(not(feature = "user"), no_std)]

#[cfg(feature = "user")]
use std::net::IpAddr;

use aya_bpf::{cty::c_char, TASK_COMM_LEN};

pub use event::*;
#[cfg(feature = "user")]
pub use helpers::*;

mod event;

#[cfg(feature = "user")]
mod helpers;

pub const CONTAINER_ID_LEN: usize = 12;
pub const IPV6_LEN: usize = 16;

const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub enum EthProtocol {
    IP,
    IPv6,
    Other,
}

impl EthProtocol {
    pub fn new(proto: u16) -> EthProtocol {
        if proto == ETH_P_IP {
            EthProtocol::IP
        } else if proto == ETH_P_IPV6 {
            EthProtocol::IPv6
        } else {
            EthProtocol::Other
        }
    }
}

const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub enum IpProtocol {
    Default,
    TCP,
    UDP,
    Other,
}

impl Default for IpProtocol {
    fn default() -> Self {
        IpProtocol::Default
    }
}

impl IpProtocol {
    pub fn new(proto: u8) -> IpProtocol {
        if proto == IPPROTO_TCP {
            IpProtocol::TCP
        } else if proto == IPPROTO_UDP {
            IpProtocol::UDP
        } else {
            IpProtocol::Other
        }
    }

    pub fn is_other(&self) -> bool {
        match self {
            IpProtocol::Default => false,
            IpProtocol::TCP => false,
            IpProtocol::UDP => false,
            IpProtocol::Other => true,
        }
    }

    #[cfg(feature = "user")]
    pub fn to_string(&self) -> String {
        match self {
            IpProtocol::TCP => "TCP".to_string(),
            IpProtocol::UDP => "UDP".to_string(),
            IpProtocol::Default | IpProtocol::Other => "UNK".to_string(),
        }
    }
}

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub enum TcAction {
    Pass,
    Drop,
}

impl TcAction {
    #[cfg(feature = "user")]
    pub fn to_string(&self) -> String {
        match self {
            TcAction::Pass => "pass".to_string(),
            TcAction::Drop => "drop".to_string(),
        }
    }
}

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
