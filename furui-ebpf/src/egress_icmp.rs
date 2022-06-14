use aya_bpf::{macros::classifier, programs::SkBuffContext};

#[classifier(name = "egress_icmp")]
pub fn egress_icmp(ctx: SkBuffContext) -> i32 {
    match unsafe { try_egress_icmp(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_egress_icmp(_ctx: SkBuffContext) -> Result<i32, i32> {
    Ok(0)
}
