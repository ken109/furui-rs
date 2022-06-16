#![no_std]
#![no_main]

#[allow(warnings)]
mod vmlinux;

mod helpers;

mod bind;
mod close;
mod connect;
mod egress;
mod egress_icmp;
mod ingress;
mod ingress_icmp;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
