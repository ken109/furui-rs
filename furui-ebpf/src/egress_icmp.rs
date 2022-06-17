use aya_bpf::cty::c_long;
use aya_bpf::{macros::classifier, programs::SkBuffContext};

#[classifier(name = "egress_icmp")]
pub fn egress_icmp(ctx: SkBuffContext) -> i32 {
    match unsafe { try_egress_icmp(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret as i32,
    }
}

unsafe fn try_egress_icmp(_ctx: SkBuffContext) -> Result<i32, c_long> {
    Ok(0)
}
