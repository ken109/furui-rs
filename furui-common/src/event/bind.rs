use aya_bpf::{
    cty::{c_char, c_ushort},
    TASK_COMM_LEN,
};

#[cfg(feature = "user")]
use crate::helpers::{family, protocol};
use crate::CONTAINER_ID_LEN;

#[derive(Copy, Clone)]
#[repr(C)]
pub struct BindEvent {
    // Only 12 characters are in the nodename, so it's 12+termination characters,
    // but I've set it to 16 for memory alignment reasons.
    pub container_id: [c_char; CONTAINER_ID_LEN],
    pub pid: u32,
    pub comm: [c_char; TASK_COMM_LEN],
    pub family: c_ushort,
    pub lport: c_ushort,
    // // Defined at the very end for memory alignment.
    pub protocol: u8,
}

#[cfg(feature = "user")]
impl BindEvent {
    pub fn family(&self) -> &'static str {
        family(self.family)
    }

    pub fn protocol(&self) -> &'static str {
        protocol(self.protocol)
    }
}
