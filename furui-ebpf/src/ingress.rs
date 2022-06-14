use aya_bpf::{macros::classifier, programs::SkBuffContext};

#[classifier(name = "ingress")]
pub fn ingress(ctx: SkBuffContext) -> i32 {
    match unsafe { try_ingress(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_ingress(_ctx: SkBuffContext) -> Result<i32, i32> {
    Ok(0)
}
