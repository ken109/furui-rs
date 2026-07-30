//! Traffic arriving at a container.

use crate::tc::handlers::tc_direction;

tc_direction! {
    classifier: ingress,
    error_message: "ingress event failed in kernel: {}",
    v4: (IngressEvent, INGRESS_EVENTS),
    v6: (Ingress6Event, INGRESS6_EVENTS),
    icmp_v4: (IngressIcmpEvent, INGRESS_ICMP_EVENTS),
    icmp_v6: (Ingress6IcmpEvent, INGRESS6_ICMP_EVENTS),
    // The container is the destination of what arrives.
    local_addr: daddr,
    local_port: dport,
}
