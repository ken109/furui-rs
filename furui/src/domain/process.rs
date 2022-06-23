use aya_bpf::cty::c_char;
use aya_bpf::TASK_COMM_LEN;

use furui_common::{IpProtocol, CONTAINER_ID_LEN};

#[derive(Debug, Clone, Default)]
pub struct Process {
    pub container_id: String,
    pub executable: String,
    pub protocol: IpProtocol,
    pub port: u16,
    pub pid: u32,
}

impl Process {
    pub fn container_id(&self) -> [c_char; CONTAINER_ID_LEN] {
        super::string_to_bytes(self.container_id.clone())
    }

    pub fn executable(&self) -> [c_char; TASK_COMM_LEN] {
        super::string_to_bytes(self.executable.clone())
    }
}
