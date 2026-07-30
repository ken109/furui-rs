//! The kernel side of furui.
//!
//! [`probes`] holds the kprobes and tracepoints that track which process owns
//! which socket; [`tc`] holds the classifiers that decide whether a packet is
//! allowed. Both consult the maps in [`maps`], which userspace fills in.

#![no_std]
#![no_main]

#[allow(warnings)]
mod vmlinux;

mod helpers;
mod maps;
mod probes;
mod tc;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
