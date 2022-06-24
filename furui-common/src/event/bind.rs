use aya_bpf::{
    cty::{c_char, c_ushort},
    TASK_COMM_LEN,
};

use crate::{EthProtocol, IpProtocol, CONTAINER_ID_LEN};

#[derive(Copy, Clone)]
#[repr(C)]
pub struct BindEvent {
    pub container_id: [c_char; CONTAINER_ID_LEN],
    pub pid: u32,
    pub comm: [c_char; TASK_COMM_LEN],
    pub family: EthProtocol,
    pub lport: c_ushort,
    pub protocol: IpProtocol,
}
