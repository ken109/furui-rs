//! Traffic leaving a container.

use crate::tc::handlers::tc_direction;

tc_direction! {
    classifier: egress,
    error_message: "egress event failed in kernel: {}",
    v4: (EgressEvent, EGRESS_EVENTS),
    v6: (Egress6Event, EGRESS6_EVENTS),
    icmp_v4: (EgressIcmpEvent, EGRESS_ICMP_EVENTS),
    icmp_v6: (Egress6IcmpEvent, EGRESS6_ICMP_EVENTS),
    // The container is the source of what leaves.
    local_addr: saddr,
    local_port: sport,
}
