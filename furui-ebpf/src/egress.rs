use aya_bpf::cty::c_long;
use aya_bpf::maps::PerfEventArray;
use aya_bpf::{
    macros::{classifier, map},
    programs::SkBuffContext,
};
use aya_log_ebpf::warn;

use furui_common::{Egress6Event, EgressEvent};

#[map]
pub(crate) static mut EGRESS_EVENTS: PerfEventArray<EgressEvent> =
    PerfEventArray::<EgressEvent>::with_max_entries(1024, 0);

#[map]
pub(crate) static mut EGRESS6_EVENTS: PerfEventArray<Egress6Event> =
    PerfEventArray::<Egress6Event>::with_max_entries(1024, 0);

#[classifier(name = "egress")]
pub fn egress(ctx: SkBuffContext) -> i32 {
    match unsafe { try_egress(&ctx) } {
        Ok(ret) => ret,
        Err(ret) => {
            if ret != 0 {
                warn!(&ctx, "egress event failed in kernel: {}", ret);
            }
            ret as i32
        }
    }
}

unsafe fn try_egress(_ctx: &SkBuffContext) -> Result<i32, c_long> {
    Ok(0)
}
