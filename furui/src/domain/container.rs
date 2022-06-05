use std::net::IpAddr;

#[derive(Debug, Clone)]
pub struct Container {
    pub(crate) id: Option<String>,
    pub(crate) ip_addresses: Option<IpAddr>,
    pub(crate) name: String,
}
