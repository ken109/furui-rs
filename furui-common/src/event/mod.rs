pub use bind::*;
pub use connect::*;
pub use egress::*;
pub use ingress::*;

mod bind;
mod connect;
mod egress;
mod ingress;

#[cfg(feature = "user")]
mod common {
    use aya_ebpf::cty::c_char;

    pub(crate) fn u8_array_to_str<const N: usize>(array: [u8; N]) -> String {
        array
            .iter()
            .map(|&s| s as char)
            .collect::<String>()
            .split('\0')
            .next()
            .unwrap_or("")
            .to_string()
    }

    pub(crate) fn c_char_array_to_str<const N: usize>(array: [c_char; N]) -> String {
        array
            .iter()
            // `c_char` is unsigned on aarch64 and signed on x86_64, so this
            // cast is a no-op on one target and load-bearing on the other.
            .map(|&s| {
                #[allow(clippy::unnecessary_cast)]
                let byte = s as u8;
                byte as char
            })
            .collect::<String>()
            .split('\0')
            .next()
            .unwrap_or("")
            .to_string()
    }
}

// Without `user` the crate is `no_std`, which leaves no test harness and no
// `Vec`. The generated code under test is the same either way.
#[cfg(all(test, feature = "user"))]
mod tests {
    use core::cell::RefCell;

    use super::*;
    use crate::{
        EthProtocol, IcmpPolicyKey, IcmpVersion, IpProtocol, PolicyKey, TcAction, CONTAINER_ID_LEN,
        TASK_COMM_LEN,
    };

    /// Which policy-key fields each generated lookup pins down, in order.
    ///
    /// The derive emits every non-empty subset of the annotated fields. This
    /// records the sequence so that a change in the generated order -- which
    /// used to vary between compilations, because the derive iterated a
    /// `HashMap` -- shows up as a test failure rather than silently.
    fn socket_search_order(event: &mut IngressEvent) -> Vec<Vec<&'static str>> {
        let seen = RefCell::new(Vec::new());
        let mut key = PolicyKey::default();

        event.search_key(&mut key, |key| {
            let mut pinned = vec![];
            if key.remote_ip != 0 {
                pinned.push("remote_ip");
            }
            if key.remote_port != 0 {
                pinned.push("remote_port");
            }
            if key.local_port != 0 {
                pinned.push("local_port");
            }
            if key.protocol != IpProtocol::default() {
                pinned.push("protocol");
            }
            seen.borrow_mut().push(pinned);
            false
        });

        seen.into_inner()
    }

    fn ingress_event() -> IngressEvent {
        IngressEvent {
            container_id: [0; CONTAINER_ID_LEN],
            saddr: 0x0A000001,
            daddr: 0,
            sport: 443,
            dport: 80,
            family: EthProtocol::IP,
            protocol: IpProtocol::TCP,
            action: TcAction::Pass,
            comm: [0; TASK_COMM_LEN],
        }
    }

    #[test]
    fn tcp_lookups_cover_every_combination_narrowest_first() {
        let order = socket_search_order(&mut ingress_event());

        assert_eq!(
            order,
            vec![
                vec!["remote_ip"],
                vec!["remote_port"],
                vec!["local_port"],
                vec!["protocol"],
                vec!["remote_ip", "remote_port"],
                vec!["remote_ip", "local_port"],
                vec!["remote_ip", "protocol"],
                vec!["remote_port", "local_port"],
                vec!["remote_port", "protocol"],
                vec!["local_port", "protocol"],
                vec!["remote_ip", "remote_port", "local_port"],
                vec!["remote_ip", "remote_port", "protocol"],
                vec!["remote_ip", "local_port", "protocol"],
                vec!["remote_port", "local_port", "protocol"],
                vec!["remote_ip", "remote_port", "local_port", "protocol"],
            ],
        );
    }

    /// `furui-ebpf/src/README.md` documents 15 socket rows and 7 ICMP rows.
    #[test]
    fn the_documented_row_counts_hold() {
        assert_eq!(socket_search_order(&mut ingress_event()).len(), 15);

        let seen = RefCell::new(0usize);
        let mut key = IcmpPolicyKey::default();
        let mut event = IngressIcmpEvent {
            container_id: [0; CONTAINER_ID_LEN],
            saddr: 0x0A000001,
            daddr: 0,
            family: EthProtocol::IP,
            protocol: IpProtocol::ICMP,
            version: IcmpVersion::V4,
            type_: 8,
            code: 0,
            action: TcAction::Pass,
        };
        event.search_key(&mut key, |_| {
            *seen.borrow_mut() += 1;
            false
        });
        assert_eq!(seen.into_inner(), 7);
    }

    #[test]
    fn the_search_stops_at_the_first_match() {
        let hits = RefCell::new(0usize);
        let mut key = PolicyKey::default();

        let matched = ingress_event().search_key(&mut key, |_| {
            *hits.borrow_mut() += 1;
            true
        });

        assert!(matched);
        assert_eq!(hits.into_inner(), 1);
    }

    /// Each derive is generated independently; ingress and egress must still
    /// probe the same number of rules.
    #[test]
    fn ingress_and_egress_probe_the_same_number_of_rules() {
        fn count<F: FnOnce(&mut PolicyKey, &dyn Fn(&PolicyKey) -> bool) -> bool>(f: F) -> usize {
            let seen = RefCell::new(0usize);
            let mut key = PolicyKey::default();
            f(&mut key, &|_| {
                *seen.borrow_mut() += 1;
                false
            });
            seen.into_inner()
        }

        let ingress = count(|key, cb| ingress_event().search_key(key, cb));
        let egress = count(|key, cb| {
            EgressEvent {
                container_id: [0; CONTAINER_ID_LEN],
                saddr: 0,
                daddr: 0x0A000001,
                sport: 80,
                dport: 443,
                family: EthProtocol::IP,
                protocol: IpProtocol::TCP,
                action: TcAction::Pass,
                comm: [0; TASK_COMM_LEN],
            }
            .search_key(key, cb)
        });

        assert_eq!(ingress, egress);
    }
}
