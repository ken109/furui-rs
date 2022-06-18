#![no_std]
#![no_main]

use aya_bpf::macros::map;
use aya_bpf::maps::HashMap;

use furui_common::{PortKey, PortVal};

#[allow(warnings)]
mod vmlinux;

mod helpers;

mod bind;
mod close;
mod connect;
mod egress;
mod egress_icmp;
mod ingress;
mod ingress_icmp;

#[map]
pub(crate) static mut PROC_PORTS: HashMap<PortKey, PortVal> = HashMap::with_max_entries(1024, 0);

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
