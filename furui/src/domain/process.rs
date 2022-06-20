#[derive(Debug, Clone)]
pub struct Process {
    pub container_id: String,
    pub executable: String,
    pub protocol: u8,
    pub port: u16,
    pub pid: i64,
}
