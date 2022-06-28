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

    pub fn to_string(&self) -> &'static str {
        match self {
            EthProtocol::IP => "IP",
            EthProtocol::IPv6 => "IPv6",
            EthProtocol::Other => "UNK",
        }
    }
}

const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_ICMP: u8 = 1;
const IPPROTO_ICMPV6: u8 = 58;

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub enum IpProtocol {
    Default,
    TCP,
    UDP,
    ICMP,
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
        } else if proto == IPPROTO_ICMP || proto == IPPROTO_ICMPV6 {
            IpProtocol::ICMP
        } else {
            IpProtocol::Other
        }
    }

    pub fn is_other(&self) -> bool {
        match self {
            IpProtocol::Default => false,
            IpProtocol::TCP => false,
            IpProtocol::UDP => false,
            IpProtocol::ICMP => false,
            IpProtocol::Other => true,
        }
    }

    pub fn to_string(&self) -> &'static str {
        match self {
            IpProtocol::TCP => "TCP",
            IpProtocol::UDP => "UDP",
            IpProtocol::ICMP => "ICMP",
            IpProtocol::Default | IpProtocol::Other => "UNK",
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
    pub fn to_string(&self) -> &'static str {
        match self {
            TcAction::Pass => "pass",
            TcAction::Drop => "drop",
        }
    }
}
