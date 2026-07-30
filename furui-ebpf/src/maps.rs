//! The maps shared with userspace.
//!
//! Userspace fills these in from the policy file and from `/proc`; the programs
//! here only read them. The names have to match the ones `furui`'s map code
//! looks up.

use aya_ebpf::{macros::map, maps::HashMap};
use furui_common::{
    ContainerID, ContainerIP, IcmpPolicyKey, IcmpPolicyValue, PolicyKey, PolicyValue, PortKey,
    PortVal,
};

/// Which process holds which port, per container.
#[map]
pub(crate) static PROC_PORTS: HashMap<PortKey, PortVal> = HashMap::with_max_entries(1024, 0);

/// Allowed TCP/UDP communications.
#[map]
pub(crate) static POLICY_LIST: HashMap<PolicyKey, PolicyValue> = HashMap::with_max_entries(1024, 0);

/// Allowed ICMP communications.
#[map]
pub(crate) static ICMP_POLICY_LIST: HashMap<IcmpPolicyKey, IcmpPolicyValue> =
    HashMap::with_max_entries(1024, 0);

/// Reverse lookup from a container's address to its id.
#[map]
pub(crate) static CONTAINER_ID_FROM_IPS: HashMap<ContainerIP, ContainerID> =
    HashMap::with_max_entries(1024, 0);
