use aya_bpf::bindings::{TC_ACT_OK, TC_ACT_SHOT};
use aya_bpf::cty::c_long;
use aya_bpf::maps::PerfEventArray;
use aya_bpf::{
    macros::{classifier, map},
    programs::SkBuffContext,
};

#[map]
pub(crate) static mut INGRESS_EVENTS: PerfEventArray<u32> =
    PerfEventArray::<u32>::with_max_entries(1024, 0);

#[classifier(name = "ingress")]
pub fn ingress(ctx: SkBuffContext) -> i32 {
    match unsafe { try_ingress(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret as i32,
    }
}

unsafe fn try_ingress(ctx: SkBuffContext) -> Result<i32, c_long> {
    INGRESS_EVENTS.output(&ctx, &0, 0);
    Ok(TC_ACT_OK)
}
