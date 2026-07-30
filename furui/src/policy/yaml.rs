//! The policy file format, as `serde` sees it.
//!
//! These types mirror the YAML one-to-one and carry no behaviour; turning
//! them into [`crate::domain`] policies is [`super::loader`]'s job.

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct ParsePolicies {
    pub policies: Vec<Policy>,
}

#[derive(Debug, Deserialize)]
pub struct Policy {
    pub container: Container,
    pub communications: Vec<Communication>,
}

#[derive(Debug, Deserialize)]
pub struct Container {
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub struct Communication {
    pub executable: Option<String>,
    #[serde(default)]
    pub sockets: Vec<Socket>,
    #[serde(default)]
    pub icmp: Vec<ICMP>,
}

#[derive(Debug, Deserialize)]
pub struct Socket {
    #[serde(default)]
    pub protocol: Protocol,
    pub local_port: Option<u16>,
    pub remote_host: Option<String>,
    pub remote_port: Option<u16>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all(deserialize = "lowercase"))]
pub enum Protocol {
    TCP,
    UDP,
    #[default]
    None,
}

#[derive(Debug, Deserialize)]
pub struct ICMP {
    #[serde(default)]
    pub version: IcmpVersion,
    #[serde(rename = "type")]
    pub type_: u8,
    pub code: Option<u8>,
    pub remote_host: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all(deserialize = "lowercase"))]
pub enum IcmpVersion {
    V4,
    V6,
    #[default]
    None,
}
