use aya_ebpf::cty::c_char;

use furui_macros::{SearchIcmpPolicyKey, SearchPolicyKey};

#[cfg(feature = "user")]
use crate::event::common;
use crate::{
    EthProtocol, IcmpPolicyKey, IcmpVersion, IpProtocol, PolicyKey, TcAction, CONTAINER_ID_LEN,
    IPV6_LEN, TASK_COMM_LEN,
};

#[derive(Copy, Clone, SearchPolicyKey)]
#[repr(C)]
pub struct EgressEvent {
    pub container_id: [c_char; CONTAINER_ID_LEN],
    pub saddr: u32,
    #[search_key(remote_ip = 0)]
    pub daddr: u32,
    #[search_key(local_port = 0)]
    pub sport: u16,
    #[search_key(remote_port = 0)]
    pub dport: u16,
    pub family: EthProtocol,
    #[search_key(protocol = IpProtocol::default())]
    pub protocol: IpProtocol,
    pub action: TcAction,
    pub comm: [u8; TASK_COMM_LEN],
}

#[cfg(feature = "user")]
impl EgressEvent {
    pub fn container_id(&self) -> String {
        common::c_char_array_to_str(self.container_id)
    }

    pub fn comm(&self) -> String {
        common::u8_array_to_str(self.comm)
    }

    pub fn src_addr(&self) -> String {
        std::net::Ipv4Addr::from(self.saddr).to_string()
    }

    pub fn dst_addr(&self) -> String {
        std::net::Ipv4Addr::from(self.daddr).to_string()
    }
}

#[derive(Copy, Clone, SearchPolicyKey)]
#[repr(C)]
pub struct Egress6Event {
    pub container_id: [c_char; CONTAINER_ID_LEN],
    pub saddr: [u8; IPV6_LEN],
    #[search_key(remote_ipv6 = [0; IPV6_LEN])]
    pub daddr: [u8; IPV6_LEN],
    #[search_key(local_port = 0)]
    pub sport: u16,
    #[search_key(remote_port = 0)]
    pub dport: u16,
    pub family: EthProtocol,
    #[search_key(protocol = IpProtocol::default())]
    pub protocol: IpProtocol,
    pub action: TcAction,
    pub comm: [u8; TASK_COMM_LEN],
}

#[cfg(feature = "user")]
impl Egress6Event {
    pub fn container_id(&self) -> String {
        common::c_char_array_to_str(self.container_id)
    }

    pub fn comm(&self) -> String {
        common::u8_array_to_str(self.comm)
    }

    pub fn src_addr(&self) -> String {
        std::net::Ipv6Addr::from(self.saddr).to_string()
    }

    pub fn dst_addr(&self) -> String {
        std::net::Ipv6Addr::from(self.daddr).to_string()
    }
}

#[derive(Copy, Clone, SearchIcmpPolicyKey)]
#[repr(C)]
pub struct EgressIcmpEvent {
    pub container_id: [c_char; CONTAINER_ID_LEN],
    pub saddr: u32,
    #[search_key(remote_ip = 0)]
    pub daddr: u32,
    pub family: EthProtocol,
    pub protocol: IpProtocol,
    pub version: IcmpVersion,
    #[search_key(type_ = 255)]
    pub type_: u8,
    #[search_key(code = 255)]
    pub code: u8,
    pub action: TcAction,
}

#[cfg(feature = "user")]
impl EgressIcmpEvent {
    pub fn container_id(&self) -> String {
        common::c_char_array_to_str(self.container_id)
    }

    pub fn src_addr(&self) -> String {
        std::net::Ipv4Addr::from(self.saddr).to_string()
    }

    pub fn dst_addr(&self) -> String {
        std::net::Ipv4Addr::from(self.daddr).to_string()
    }
}

#[derive(Copy, Clone, SearchIcmpPolicyKey)]
#[repr(C)]
pub struct Egress6IcmpEvent {
    pub container_id: [c_char; CONTAINER_ID_LEN],
    pub saddr: [u8; IPV6_LEN],
    #[search_key(remote_ipv6 = [0; IPV6_LEN])]
    pub daddr: [u8; IPV6_LEN],
    pub family: EthProtocol,
    pub protocol: IpProtocol,
    pub version: IcmpVersion,
    #[search_key(type_ = 255)]
    pub type_: u8,
    #[search_key(code = 255)]
    pub code: u8,
    pub action: TcAction,
}

#[cfg(feature = "user")]
impl Egress6IcmpEvent {
    pub fn container_id(&self) -> String {
        common::c_char_array_to_str(self.container_id)
    }

    pub fn src_addr(&self) -> String {
        std::net::Ipv6Addr::from(self.saddr).to_string()
    }

    pub fn dst_addr(&self) -> String {
        std::net::Ipv6Addr::from(self.daddr).to_string()
    }
}
