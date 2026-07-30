//! The events the tc classifiers report.
//!
//! Ingress and egress differ in one thing: which end of the connection is the
//! remote one. On the way in the remote end is the source, on the way out it is
//! the destination. The fields, the accessors and the policy lookups derived
//! from them are otherwise identical, so all eight types come from one
//! definition.
//!
//! The remote-side fields are declared first so that both directions probe the
//! policy map in the same order -- `SearchPolicyKey` generates its lookups in
//! field-declaration order, and `../../../furui-ebpf/src/README.md` documents
//! one order for both.

use furui_macros::{SearchIcmpPolicyKey, SearchPolicyKey};

#[cfg(feature = "user")]
use crate::event::common;
use crate::{
    cty::c_char, EthProtocol, IcmpPolicyKey, IcmpVersion, IpProtocol, PolicyKey, TcAction,
    CONTAINER_ID_LEN, IPV6_LEN, TASK_COMM_LEN,
};

/// Defines the four event types for one direction.
///
/// `remote`/`local` and `remote_port`/`local_port` name which of `saddr`,
/// `daddr`, `sport` and `dport` plays each role. The accessors can still refer
/// to `saddr` and `sport` literally, because those fields exist either way --
/// only their role changes.
macro_rules! traffic_events {
    (
        tcp_udp_v4: $v4:ident,
        tcp_udp_v6: $v6:ident,
        icmp_v4: $icmp_v4:ident,
        icmp_v6: $icmp_v6:ident,
        remote: $remote:ident,
        local: $local:ident,
        remote_port: $remote_port:ident,
        local_port: $local_port:ident,
    ) => {
        #[derive(Copy, Clone, SearchPolicyKey)]
        #[repr(C)]
        pub struct $v4 {
            pub container_id: [c_char; CONTAINER_ID_LEN],
            #[search_key(remote_ip = 0)]
            pub $remote: u32,
            pub $local: u32,
            #[search_key(remote_port = 0)]
            pub $remote_port: u16,
            #[search_key(local_port = 0)]
            pub $local_port: u16,
            pub family: EthProtocol,
            #[search_key(protocol = IpProtocol::default())]
            pub protocol: IpProtocol,
            pub action: TcAction,
            pub comm: [u8; TASK_COMM_LEN],
        }

        #[derive(Copy, Clone, SearchPolicyKey)]
        #[repr(C)]
        pub struct $v6 {
            pub container_id: [c_char; CONTAINER_ID_LEN],
            #[search_key(remote_ipv6 = [0; IPV6_LEN])]
            pub $remote: [u8; IPV6_LEN],
            pub $local: [u8; IPV6_LEN],
            #[search_key(remote_port = 0)]
            pub $remote_port: u16,
            #[search_key(local_port = 0)]
            pub $local_port: u16,
            pub family: EthProtocol,
            #[search_key(protocol = IpProtocol::default())]
            pub protocol: IpProtocol,
            pub action: TcAction,
            pub comm: [u8; TASK_COMM_LEN],
        }

        #[derive(Copy, Clone, SearchIcmpPolicyKey)]
        #[repr(C)]
        pub struct $icmp_v4 {
            pub container_id: [c_char; CONTAINER_ID_LEN],
            #[search_key(remote_ip = 0)]
            pub $remote: u32,
            pub $local: u32,
            pub family: EthProtocol,
            pub protocol: IpProtocol,
            pub version: IcmpVersion,
            #[search_key(type_ = 255)]
            pub type_: u8,
            #[search_key(code = 255)]
            pub code: u8,
            pub action: TcAction,
        }

        #[derive(Copy, Clone, SearchIcmpPolicyKey)]
        #[repr(C)]
        pub struct $icmp_v6 {
            pub container_id: [c_char; CONTAINER_ID_LEN],
            #[search_key(remote_ipv6 = [0; IPV6_LEN])]
            pub $remote: [u8; IPV6_LEN],
            pub $local: [u8; IPV6_LEN],
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
        const _: () = {
            impl $v4 {
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

            impl $v6 {
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

            impl $icmp_v4 {
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

            impl $icmp_v6 {
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
        };
    };
}

traffic_events! {
    tcp_udp_v4: IngressEvent,
    tcp_udp_v6: Ingress6Event,
    icmp_v4: IngressIcmpEvent,
    icmp_v6: Ingress6IcmpEvent,
    // Traffic arriving at the container: the remote end sent it.
    remote: saddr,
    local: daddr,
    remote_port: sport,
    local_port: dport,
}

traffic_events! {
    tcp_udp_v4: EgressEvent,
    tcp_udp_v6: Egress6Event,
    icmp_v4: EgressIcmpEvent,
    icmp_v6: Egress6IcmpEvent,
    // Traffic leaving the container: the remote end receives it.
    remote: daddr,
    local: saddr,
    remote_port: dport,
    local_port: sport,
}
