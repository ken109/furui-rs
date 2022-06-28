use aya_bpf_cty::c_char;

use crate::{
    EthProtocol, IcmpVersion, IpProtocol, TcAction, CONTAINER_ID_LEN, IPV6_LEN, TASK_COMM_LEN,
};

#[derive(Copy, Clone)]
#[repr(C)]
pub struct EgressEvent {
    pub container_id: [c_char; CONTAINER_ID_LEN],
    pub saddr: u32,
    pub daddr: u32,
    pub sport: u16,
    pub dport: u16,
    pub family: EthProtocol,
    pub protocol: IpProtocol,
    pub action: TcAction,
    pub comm: [c_char; TASK_COMM_LEN],
}

#[cfg(feature = "user")]
impl EgressEvent {
    pub fn src_addr(&self) -> String {
        std::net::Ipv4Addr::from(self.saddr).to_string()
    }

    pub fn dst_addr(&self) -> String {
        std::net::Ipv4Addr::from(self.daddr).to_string()
    }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct Egress6Event {
    pub container_id: [c_char; CONTAINER_ID_LEN],
    pub saddr: [u8; IPV6_LEN],
    pub daddr: [u8; IPV6_LEN],
    pub sport: u16,
    pub dport: u16,
    pub family: EthProtocol,
    pub protocol: IpProtocol,
    pub action: TcAction,
    pub comm: [c_char; TASK_COMM_LEN],
}

#[cfg(feature = "user")]
impl Egress6Event {
    pub fn src_addr(&self) -> String {
        std::net::Ipv6Addr::from(self.saddr).to_string()
    }

    pub fn dst_addr(&self) -> String {
        std::net::Ipv6Addr::from(self.daddr).to_string()
    }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct EgressIcmpEvent {
    pub container_id: [c_char; CONTAINER_ID_LEN],
    pub saddr: u32,
    pub daddr: u32,
    pub family: EthProtocol,
    pub protocol: IpProtocol,
    pub version: IcmpVersion,
    pub type_: u8,
    pub code: u8,
    pub action: TcAction,
}

#[cfg(feature = "user")]
impl EgressIcmpEvent {
    pub fn src_addr(&self) -> String {
        std::net::Ipv4Addr::from(self.saddr).to_string()
    }

    pub fn dst_addr(&self) -> String {
        std::net::Ipv4Addr::from(self.daddr).to_string()
    }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct Egress6IcmpEvent {
    pub container_id: [c_char; CONTAINER_ID_LEN],
    pub saddr: [u8; IPV6_LEN],
    pub daddr: [u8; IPV6_LEN],
    pub family: EthProtocol,
    pub protocol: IpProtocol,
    pub version: IcmpVersion,
    pub type_: u8,
    pub code: u8,
    pub action: TcAction,
}

#[cfg(feature = "user")]
impl Egress6IcmpEvent {
    pub fn src_addr(&self) -> String {
        std::net::Ipv6Addr::from(self.saddr).to_string()
    }

    pub fn dst_addr(&self) -> String {
        std::net::Ipv6Addr::from(self.daddr).to_string()
    }
}
