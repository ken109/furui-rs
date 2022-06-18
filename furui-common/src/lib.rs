#![cfg_attr(not(feature = "user"), no_std)]

use aya_bpf::{cty::c_char, TASK_COMM_LEN};

pub use event::*;

mod event;

#[cfg(feature = "user")]
mod helpers;

pub const CONTAINER_ID_LEN: usize = 16;

#[derive(Copy, Clone)]
pub struct PortKey {
    pub container_id: [c_char; CONTAINER_ID_LEN],
    pub port: u16,
    pub proto: u8,
}

#[derive(Copy, Clone)]
pub struct PortVal {
    pub comm: [c_char; TASK_COMM_LEN],
}
