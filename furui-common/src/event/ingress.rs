use aya_bpf::cty::c_char;
use aya_bpf::TASK_COMM_LEN;

#[cfg(feature = "user")]
use crate::helpers::protocol_value_to_str;
use crate::{IpProtocol, TcAction, IPV6_LEN};

#[derive(Copy, Clone)]
#[repr(C)]
pub struct IngressEvent {
    pub saddr: u32,
    pub daddr: u32,
    pub sport: u16,
    pub dport: u16,
    pub protocol: IpProtocol,
    pub action: TcAction,
    pub comm: [c_char; TASK_COMM_LEN],
}

#[cfg(feature = "user")]
impl IngressEvent {
    pub fn src_addr(&self) -> String {
        std::net::Ipv4Addr::from(self.saddr).to_string()
    }

    pub fn dst_addr(&self) -> String {
        std::net::Ipv4Addr::from(self.daddr).to_string()
    }

    pub fn protocol(&self) -> String {
        self.protocol.to_string()
    }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct Ingress6Event {
    pub saddr: [c_char; IPV6_LEN],
    pub daddr: [c_char; IPV6_LEN],
    pub sport: u16,
    pub dport: u16,
    pub protocol: IpProtocol,
    pub action: TcAction,
    pub comm: [c_char; TASK_COMM_LEN],
}

#[cfg(feature = "user")]
impl Ingress6Event {
    pub fn src_addr(&self) -> String {
        std::net::Ipv6Addr::from(self.saddr).to_string()
    }

    pub fn dst_addr(&self) -> String {
        std::net::Ipv6Addr::from(self.daddr).to_string()
    }

    pub fn protocol(&self) -> String {
        self.protocol.to_string()
    }
}
