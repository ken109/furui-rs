#![no_std]
#![no_main]

mod bind;
mod close;
mod connect;
mod egress;
mod egress_icmp;
mod ingress;
mod ingress_icmp;

#[allow(warnings)]
mod vmlinux;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
