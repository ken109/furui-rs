#![no_std]
#![no_main]

use aya_bpf::{
    macros::classifier,
    programs::SkBuffContext,
};

#[allow(warnings)]
mod vmlinux;


#[classifier(name = "ingress_icmp")]
pub fn ingress_icmp(ctx: SkBuffContext) -> i32 {
    match unsafe { try_ingress_icmp(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_ingress_icmp(_ctx: SkBuffContext) -> Result<i32, i32> {
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
