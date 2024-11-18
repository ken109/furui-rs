use aya_ebpf::cty::{c_char, c_ushort};

#[cfg(feature = "user")]
use crate::event::common;
use crate::{EthProtocol, IpProtocol, CONTAINER_ID_LEN, TASK_COMM_LEN};

#[derive(Copy, Clone)]
#[repr(C)]
pub struct BindEvent {
    pub container_id: [c_char; CONTAINER_ID_LEN],
    pub pid: u32,
    pub comm: [u8; TASK_COMM_LEN],
    pub family: EthProtocol,
    pub lport: c_ushort,
    pub protocol: IpProtocol,
}

#[cfg(feature = "user")]
impl BindEvent {
    pub fn container_id(&self) -> String {
        common::c_char_array_to_str(self.container_id)
    }

    pub fn comm(&self) -> String {
        common::u8_array_to_str(self.comm)
    }
}
