use std::fs::File;
use std::io::Read;
use std::path::PathBuf;

use serde_derive::Deserialize;
use serde_yaml;

#[derive(Debug, Deserialize)]
pub struct Policies {
    policies: Vec<Policy>,
}

#[derive(Debug, Deserialize)]
pub struct Policy {
    container: Container,
    communications: Vec<Communication>,
}

#[derive(Debug, Deserialize)]
pub struct Container {
    name: String,
}

#[derive(Debug, Deserialize)]
pub struct Communication {
    executable: String,
    sockets: Vec<Socket>,
}

#[derive(Debug, Deserialize)]
pub struct Socket {
    protocol: Protocol,
    local_port: Option<u16>,
    remote_ip: Option<String>,
    remote_port: Option<u16>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all(deserialize = "lowercase"))]
pub enum Protocol {
    TCP,
    UDP,
}

impl Policies {
    pub fn new(path: PathBuf) -> anyhow::Result<Vec<Policy>> {
        let mut f = File::open(path.as_path()).expect("file not found");
        let mut contents = String::new();

        f.read_to_string(&mut contents)?;

        Ok(serde_yaml::from_str::<Policies>(&contents)?.policies)
    }
}
