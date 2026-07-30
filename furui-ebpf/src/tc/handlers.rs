//! The classifier body, shared by both directions.
//!
//! Ingress and egress run the same checks; they disagree only about which end
//! of the packet belongs to the container. On the way in that is the
//! destination, on the way out it is the source. Everything downstream -- the
//! container lookup, the port-to-process lookup, and the policy search -- is
//! identical, so both directions expand from this one definition.

/// Generates the four packet handlers and the classifier entry point for one
/// direction.
///
/// `local_addr` and `local_port` name the event fields holding the container's
/// own address and port.
macro_rules! tc_direction {
    (
        classifier: $classifier:ident,
        // `aya_log_ebpf` needs a literal format string, so the whole message is
        // a parameter rather than something assembled from a name.
        error_message: $error_message:literal,
        v4: ($v4_event:ident, $v4_array:ident),
        v6: ($v6_event:ident, $v6_array:ident),
        icmp_v4: ($icmp_v4_event:ident, $icmp_v4_array:ident),
        icmp_v6: ($icmp_v6_event:ident, $icmp_v6_array:ident),
        local_addr: $local_addr:ident,
        local_port: $local_port:ident,
    ) => {
        use aya_ebpf::{
            bindings::{TC_ACT_OK, TC_ACT_SHOT},
            cty::c_long,
            helpers::bpf_probe_read_kernel,
            macros::{classifier, map},
            maps::PerfEventArray,
            programs::TcContext,
        };
        use aya_log_ebpf::warn;
        use furui_common::{
            $icmp_v4_event, $icmp_v6_event, $v4_event, $v6_event, ContainerIP, EthProtocol,
            IcmpPolicyKey, IcmpVersion, IpProtocol, PolicyKey, PortKey, TcAction,
        };

        use crate::{
            helpers::{
                eth_protocol, get_port, ip_protocol, ntohl, ETH_HDR_LEN, IPV6_HDR_LEN, IP_HDR_LEN,
                NEIGHBOR_ADVERTISEMENT, NEIGHBOR_SOLICITAION,
            },
            maps::{CONTAINER_ID_FROM_IPS, ICMP_POLICY_LIST, POLICY_LIST, PROC_PORTS},
            vmlinux::{icmphdr, iphdr, ipv6hdr},
        };

        #[map]
        static $v4_array: PerfEventArray<$v4_event> = PerfEventArray::<$v4_event>::new(0);

        #[map]
        static $v6_array: PerfEventArray<$v6_event> = PerfEventArray::<$v6_event>::new(0);

        #[map]
        static $icmp_v4_array: PerfEventArray<$icmp_v4_event> =
            PerfEventArray::<$icmp_v4_event>::new(0);

        #[map]
        static $icmp_v6_array: PerfEventArray<$icmp_v6_event> =
            PerfEventArray::<$icmp_v6_event>::new(0);

        /// Reports the verdict and turns it into a tc return code.
        macro_rules! finish {
            ($ctx:expr, $action:expr, $event:expr, $array:ident) => {{
                let action = $action;
                $event.action = action;
                $array.output($ctx, $event, 0);
                Ok(match action {
                    TcAction::Pass => TC_ACT_OK,
                    TcAction::Drop => TC_ACT_SHOT,
                })
            }};
        }

        /// Looks the policy up for a TCP/UDP packet whose addresses and ports
        /// are already filled in.
        ///
        /// Returns `None` when the packet does not belong to a container we
        /// know about, in which case the caller drops it without reporting.
        macro_rules! decide_tcp_udp {
            ($ctx:expr, $event:expr, $ip_key:expr, $array:ident) => {{
                let cid_val = CONTAINER_ID_FROM_IPS.get(&$ip_key);
                if cid_val.is_none() {
                    return Ok(TC_ACT_SHOT);
                }

                $event.container_id = bpf_probe_read_kernel(&cid_val.unwrap().container_id)?;

                let mut port_key: PortKey = core::mem::zeroed();
                port_key.container_id = $event.container_id;
                port_key.port = $event.$local_port;
                port_key.proto = $event.protocol;

                let port_val = PROC_PORTS.get(&port_key);
                if port_val.is_none() {
                    return finish!($ctx, TcAction::Drop, &mut $event, $array);
                }
                let port_val = port_val.unwrap();

                let mut policy_key: PolicyKey = core::mem::zeroed();

                // If nothing is specified in the policy except the container
                // name and executable name, allow all communication to that
                // process.
                policy_key.container_id = $event.container_id;
                policy_key.comm = bpf_probe_read_kernel(&port_val.comm)?;
                if POLICY_LIST.get(&policy_key).is_some() {
                    return finish!($ctx, TcAction::Pass, &mut $event, $array);
                }

                $event.comm = bpf_probe_read_kernel(&port_val.comm)?;

                if $event.search_key(&mut policy_key, |policy_key| {
                    POLICY_LIST.get(policy_key).is_some()
                }) {
                    return finish!($ctx, TcAction::Pass, &mut $event, $array);
                }

                finish!($ctx, TcAction::Drop, &mut $event, $array)
            }};
        }

        /// As [`decide_tcp_udp`], for ICMP: no port, and the policy is keyed by
        /// type and code instead.
        macro_rules! decide_icmp {
            ($ctx:expr, $event:expr, $ip_key:expr, $array:ident) => {{
                let cid_val = CONTAINER_ID_FROM_IPS.get(&$ip_key);
                if cid_val.is_none() {
                    return Ok(TC_ACT_SHOT);
                }

                $event.container_id = bpf_probe_read_kernel(&cid_val.unwrap().container_id)?;

                let mut policy_key: IcmpPolicyKey = core::mem::zeroed();
                policy_key.container_id = $event.container_id;
                policy_key.version = $event.version;

                if $event.search_key(&mut policy_key, |policy_key| {
                    ICMP_POLICY_LIST.get(policy_key).is_some()
                }) {
                    return finish!($ctx, TcAction::Pass, &mut $event, $array);
                }

                finish!($ctx, TcAction::Drop, &mut $event, $array)
            }};
        }

        unsafe fn ipv4_tcp_udp(ctx: &TcContext) -> Result<i32, c_long> {
            let mut event: $v4_event = core::mem::zeroed();

            let iph = ctx.load::<iphdr>(ETH_HDR_LEN)?;

            event.saddr = ntohl(iph.__bindgen_anon_1.__bindgen_anon_1.saddr);
            event.daddr = ntohl(iph.__bindgen_anon_1.__bindgen_anon_1.daddr);
            (event.sport, event.dport) = get_port(ctx)?;

            event.family = eth_protocol(ctx)?;
            event.protocol = ip_protocol(ctx)?;

            let mut ip_key: ContainerIP = core::mem::zeroed();
            ip_key.ip = event.$local_addr;

            decide_tcp_udp!(ctx, event, ip_key, $v4_array)
        }

        unsafe fn ipv6_tcp_udp(ctx: &TcContext) -> Result<i32, c_long> {
            let mut event: $v6_event = core::mem::zeroed();

            let iph = ctx.load::<ipv6hdr>(ETH_HDR_LEN)?;

            event.saddr =
                bpf_probe_read_kernel(&iph.__bindgen_anon_1.__bindgen_anon_1.saddr.in6_u.u6_addr8)?;
            event.daddr =
                bpf_probe_read_kernel(&iph.__bindgen_anon_1.__bindgen_anon_1.daddr.in6_u.u6_addr8)?;
            (event.sport, event.dport) = get_port(ctx)?;

            event.family = eth_protocol(ctx)?;
            event.protocol = ip_protocol(ctx)?;

            let mut ip_key: ContainerIP = core::mem::zeroed();
            ip_key.ipv6 = event.$local_addr;

            decide_tcp_udp!(ctx, event, ip_key, $v6_array)
        }

        unsafe fn ipv4_icmp(ctx: &TcContext) -> Result<i32, c_long> {
            let mut event: $icmp_v4_event = core::mem::zeroed();

            let iph = ctx.load::<iphdr>(ETH_HDR_LEN)?;

            event.saddr = ntohl(iph.__bindgen_anon_1.__bindgen_anon_1.saddr);
            event.daddr = ntohl(iph.__bindgen_anon_1.__bindgen_anon_1.daddr);

            event.family = eth_protocol(ctx)?;
            event.protocol = ip_protocol(ctx)?;

            let icmph = ctx.load::<icmphdr>(ETH_HDR_LEN + IP_HDR_LEN)?;
            event.version = IcmpVersion::V4;
            event.type_ = icmph.type_;
            event.code = icmph.code;

            let mut ip_key: ContainerIP = core::mem::zeroed();
            ip_key.ip = event.$local_addr;

            decide_icmp!(ctx, event, ip_key, $icmp_v4_array)
        }

        unsafe fn ipv6_icmp(ctx: &TcContext) -> Result<i32, c_long> {
            let mut event: $icmp_v6_event = core::mem::zeroed();

            let iph = ctx.load::<ipv6hdr>(ETH_HDR_LEN)?;

            event.saddr =
                bpf_probe_read_kernel(&iph.__bindgen_anon_1.__bindgen_anon_1.saddr.in6_u.u6_addr8)?;
            event.daddr =
                bpf_probe_read_kernel(&iph.__bindgen_anon_1.__bindgen_anon_1.daddr.in6_u.u6_addr8)?;

            event.family = eth_protocol(ctx)?;
            event.protocol = ip_protocol(ctx)?;

            let icmph = ctx.load::<icmphdr>(ETH_HDR_LEN + IPV6_HDR_LEN)?;
            event.version = IcmpVersion::V6;
            event.type_ = icmph.type_;
            event.code = icmph.code;

            // Neighbour discovery is how IPv6 resolves link-layer addresses at
            // all; policing it would break the container's networking before a
            // policy could ever apply.
            if event.type_ == NEIGHBOR_SOLICITAION || event.type_ == NEIGHBOR_ADVERTISEMENT {
                return Ok(TC_ACT_OK);
            }

            let mut ip_key: ContainerIP = core::mem::zeroed();
            ip_key.ipv6 = event.$local_addr;

            decide_icmp!(ctx, event, ip_key, $icmp_v6_array)
        }

        #[classifier]
        pub fn $classifier(ctx: TcContext) -> i32 {
            match unsafe { dispatch(&ctx) } {
                Ok(ret) => ret,
                Err(ret) => {
                    if ret != 0 {
                        warn!(&ctx, $error_message, ret);
                    }
                    ret as i32
                }
            }
        }

        unsafe fn dispatch(ctx: &TcContext) -> Result<i32, c_long> {
            match (eth_protocol(ctx)?, ip_protocol(ctx)?) {
                (EthProtocol::IP, IpProtocol::TCP | IpProtocol::UDP) => ipv4_tcp_udp(ctx),
                (EthProtocol::IP, IpProtocol::ICMP) => ipv4_icmp(ctx),
                (EthProtocol::IPv6, IpProtocol::TCP | IpProtocol::UDP) => ipv6_tcp_udp(ctx),
                (EthProtocol::IPv6, IpProtocol::ICMP) => ipv6_icmp(ctx),
                _ => Ok(TC_ACT_OK),
            }
        }
    };
}

pub(crate) use tc_direction;
