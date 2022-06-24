#![cfg_attr(not(feature = "user"), no_std)]

use aya_bpf_cty::c_ushort;

pub use event::*;
#[cfg(feature = "user")]
pub use helpers::*;
pub use map::*;

mod event;
#[cfg(feature = "user")]
mod helpers;
mod map;

pub const TASK_COMM_LEN: usize = 16;
pub const CONTAINER_ID_LEN: usize = 12;
pub const IPV6_LEN: usize = 16;

const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;

const AF_INET: c_ushort = 2;
const AF_INET6: c_ushort = 10;

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub enum EthProtocol {
    IP,
    IPv6,
    Other,
}

impl EthProtocol {
    pub fn from_eth(proto: u16) -> EthProtocol {
        if proto == ETH_P_IP {
            EthProtocol::IP
        } else if proto == ETH_P_IPV6 {
            EthProtocol::IPv6
        } else {
            EthProtocol::Other
        }
    }

    pub fn from_family(proto: c_ushort) -> EthProtocol {
        if proto == AF_INET {
            EthProtocol::IP
        } else if proto == AF_INET6 {
            EthProtocol::IPv6
        } else {
            EthProtocol::Other
        }
    }

    pub fn is_ip(&self) -> bool {
        match self {
            EthProtocol::IP => true,
            EthProtocol::IPv6 => false,
            EthProtocol::Other => false,
        }
    }

    pub fn is_ipv6(&self) -> bool {
        match self {
            EthProtocol::IP => false,
            EthProtocol::IPv6 => true,
            EthProtocol::Other => false,
        }
    }

    pub fn is_other(&self) -> bool {
        match self {
            EthProtocol::IP => false,
            EthProtocol::IPv6 => false,
            EthProtocol::Other => true,
        }
    }

    #[cfg(feature = "user")]
    pub fn to_string(&self) -> String {
        match self {
            EthProtocol::IP => "IP".to_string(),
            EthProtocol::IPv6 => "IP".to_string(),
            EthProtocol::Other => "UNK".to_string(),
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
