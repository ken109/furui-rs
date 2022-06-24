use aya_bpf_cty::{c_char, c_ushort};

use crate::{EthProtocol, IpProtocol, CONTAINER_ID_LEN, TASK_COMM_LEN};

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
