use aya_bpf_cty::c_char;

use crate::{EthProtocol, IpProtocol, CONTAINER_ID_LEN, IPV6_LEN, TASK_COMM_LEN};

#[derive(Copy, Clone)]
#[repr(C)]
pub struct ConnectEvent {
    pub container_id: [c_char; CONTAINER_ID_LEN],
    pub pid: u32,
    pub comm: [c_char; TASK_COMM_LEN],
    pub src_addr: u32,
    pub dst_addr: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub family: EthProtocol,
    pub protocol: IpProtocol,
}

#[cfg(feature = "user")]
impl ConnectEvent {
    pub fn src_addr(&self) -> String {
        std::net::Ipv4Addr::from(self.src_addr).to_string()
    }

    pub fn dst_addr(&self) -> String {
        std::net::Ipv4Addr::from(self.dst_addr).to_string()
    }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct Connect6Event {
    pub container_id: [c_char; CONTAINER_ID_LEN],
    pub pid: u32,
    pub comm: [c_char; TASK_COMM_LEN],
    pub src_addr: [u8; IPV6_LEN],
    pub dst_addr: [u8; IPV6_LEN],
    pub src_port: u16,
    pub dst_port: u16,
    pub family: EthProtocol,
    pub protocol: IpProtocol,
}

#[cfg(feature = "user")]
impl Connect6Event {
    pub fn src_addr(&self) -> String {
        std::net::Ipv6Addr::from(self.src_addr).to_string()
    }

    pub fn dst_addr(&self) -> String {
        std::net::Ipv6Addr::from(self.dst_addr).to_string()
    }
}
