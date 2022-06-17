use aya_bpf::cty::c_long;
use aya_bpf::{macros::classifier, programs::SkBuffContext};

#[classifier(name = "ingress_icmp")]
pub fn ingress_icmp(ctx: SkBuffContext) -> i32 {
    match unsafe { try_ingress_icmp(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret as i32,
    }
}

unsafe fn try_ingress_icmp(_ctx: SkBuffContext) -> Result<i32, c_long> {
    Ok(0)
}
