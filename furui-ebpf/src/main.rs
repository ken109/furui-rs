#![no_std]
#![no_main]

use aya_bpf::{
    macros::classifier,
    programs::SkBuffContext,
};

#[classifier(name="furui")]
pub fn furui(ctx: SkBuffContext) -> i32 {
    match unsafe { try_furui(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_furui(_ctx: SkBuffContext) -> Result<i32, i32> {
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
