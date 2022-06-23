use aya_bpf::cty::c_long;
use aya_bpf::maps::PerfEventArray;
use aya_bpf::{
    macros::{classifier, map},
    programs::SkBuffContext,
};

#[map]
pub(crate) static mut EGRESS_EVENTS: PerfEventArray<u32> =
    PerfEventArray::<u32>::with_max_entries(1024, 0);

#[classifier(name = "egress")]
pub fn egress(ctx: SkBuffContext) -> i32 {
    match unsafe { try_egress(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret as i32,
    }
}

unsafe fn try_egress(ctx: SkBuffContext) -> Result<i32, c_long> {
    EGRESS_EVENTS.output(&ctx, &0, 0);
    Ok(0)
}
