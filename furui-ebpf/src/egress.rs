use aya_bpf::cty::c_ushort;
use aya_bpf::{macros::classifier, programs::SkBuffContext};

#[classifier(name = "egress")]
pub fn egress(ctx: SkBuffContext) -> i32 {
    match unsafe { try_egress(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret as i32,
    }
}

unsafe fn try_egress(_ctx: SkBuffContext) -> Result<i32, c_ushort> {
    Ok(0)
}
