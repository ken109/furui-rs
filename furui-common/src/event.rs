use aya_bpf::{
    cty::{c_char, c_ushort},
    TASK_COMM_LEN,
};

#[cfg(feature = "user")]
use crate::helpers::{family, protocol};
use crate::CONTAINER_ID_LEN;

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
    pub protocol: u8,
}

#[cfg(feature = "user")]
impl BindEvent {
    pub fn family(&self) -> &'static str {
        family(self.family)
    }

    pub fn protocol(&self) -> &'static str {
        protocol(self.protocol)
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
    pub src_addr: u32,
    pub dst_addr: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub family: c_ushort,
    pub protocol: u8,
}

#[cfg(feature = "user")]
impl ConnectEvent {
    pub fn src_addr(&self) -> String {
        std::net::Ipv4Addr::from(self.src_addr).to_string()
    }

    pub fn dst_addr(&self) -> String {
        std::net::Ipv4Addr::from(self.dst_addr).to_string()
    }

    pub fn family(&self) -> &'static str {
        family(self.family)
    }

    pub fn protocol(&self) -> &'static str {
        protocol(self.protocol)
    }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct Connect6Event {
    // Only 12 characters are in the nodename, so it's 12+termination characters,
    // but I've set it to 16 for memory alignment reasons.
    pub container_id: [c_char; CONTAINER_ID_LEN],
    pub pid: u32,
    pub comm: [c_char; TASK_COMM_LEN],
    pub src_addr: [c_char; 16],
    pub dst_addr: [c_char; 16],
    pub src_port: u16,
    pub dst_port: u16,
    pub family: c_ushort,
    pub protocol: u8,
}

#[cfg(feature = "user")]
impl Connect6Event {
    pub fn src_addr(&self) -> String {
        std::net::Ipv6Addr::from(self.src_addr).to_string()
    }

    pub fn dst_addr(&self) -> String {
        std::net::Ipv6Addr::from(self.dst_addr).to_string()
    }

    pub fn family(&self) -> &'static str {
        family(self.family)
    }

    pub fn protocol(&self) -> &'static str {
        protocol(self.protocol)
    }
}

#[cfg(feature = "user")]
mod user {
    use super::*;

    unsafe impl aya::Pod for BindEvent {}
    unsafe impl aya::Pod for ConnectEvent {}
    unsafe impl aya::Pod for Connect6Event {}
}
