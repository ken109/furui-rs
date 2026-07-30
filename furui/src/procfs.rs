use std::{
    fs::File,
    io::{BufRead, BufReader, Read},
    path::Path,
    str::FromStr,
    sync::Arc,
};

use furui_common::IpProtocol;
use tokio::sync::Mutex;
use tracing::error;

use crate::domain::{Containers, Process};

static SUPPORTED_PROTOCOLS: [(&str, IpProtocol); 4] = [
    ("tcp", IpProtocol::TCP),
    ("udp", IpProtocol::UDP),
    ("tcp6", IpProtocol::TCP),
    ("udp6", IpProtocol::UDP),
];

pub async fn listening_processes(containers: Arc<Mutex<Containers>>) -> Vec<Process> {
    let mut processes = vec![];

    for container in containers.lock().await.list() {
        for (supported_protocol, proto) in &SUPPORTED_PROTOCOLS {
            let net_file_path = Path::new("/proc")
                .join(format!("{}", container.pid))
                .join("net")
                .join(supported_protocol);

            let net_file = match File::open(net_file_path) {
                Ok(file) => file,
                Err(_) => continue,
            };

            let mut net_file_buf = BufReader::new(net_file).lines();
            net_file_buf.next();

            while let Some(Ok(line)) = net_file_buf.next() {
                let Some((port, inode)) = parse_net_row(&line) else {
                    continue;
                };

                let (executable, pid) = match search_process_from_inode(container.pid, inode) {
                    Some(value) => value,
                    None => continue,
                };

                processes.push(Process {
                    container_id: container.id.clone().unwrap(),
                    executable,
                    protocol: *proto,
                    port,
                    pid,
                })
            }
        }
    }

    processes
}

/// Reads the local port and socket inode out of one `/proc/net/{tcp,udp}` row.
///
/// Rows look like
///
/// ```text
///   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
///    0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000  00000000     0        0 24052
/// ```
///
/// Returns `None` for the header and for anything else that does not parse,
/// rather than indexing into a short row.
fn parse_net_row(line: &str) -> Option<(u16, u64)> {
    let mut columns = line.split_whitespace();

    let local_address = columns.nth(1)?;
    let port = u16::from_str_radix(local_address.rsplit_once(':')?.1, 16).ok()?;

    // `sl` and `local_address` are already consumed, so the inode is the eighth
    // column from here.
    let inode = columns.nth(7)?.parse().ok()?;

    Some((port, inode))
}

fn search_process_from_inode(pid: u32, inode: u64) -> Option<(String, u32)> {
    let container_shim_pid = get_ppid(pid);

    let child_pids = get_child_pids(container_shim_pid);

    for child_pid in child_pids {
        if inode_exists(child_pid, inode) {
            return Some((get_process_name(child_pid), child_pid));
        }
    }

    None
}

fn get_ppid(pid: u32) -> u32 {
    let path = Path::new("/proc").join(format!("{}", pid)).join("stat");

    let file = match File::open(path) {
        Ok(file) => file,
        Err(_) => return 0,
    };

    let mut file_buf = BufReader::new(file).lines();
    u32::from_str(
        file_buf
            .next()
            .unwrap()
            .unwrap()
            .split_whitespace()
            .collect::<Vec<&str>>()[3],
    )
    .unwrap_or(0)
}

fn get_child_pids(pid: u32) -> Vec<u32> {
    let mut pid = pid;

    let mut search_stack: Vec<u32> = vec![];
    let mut pids = vec![];

    loop {
        let path = Path::new("/proc")
            .join(format!("{}", pid))
            .join("task")
            .join(format!("{}", pid))
            .join("children");

        let file = match File::open(path) {
            Ok(file) => file,
            Err(_) => return vec![],
        };

        let mut file_buf = BufReader::new(file).lines();

        let child_pids = match file_buf.next() {
            Some(line) => line
                .unwrap()
                .split_whitespace()
                .map(|pid| pid.parse::<u32>().unwrap())
                .collect::<Vec<u32>>(),
            None => vec![],
        };

        for child_pid in child_pids {
            search_stack.push(child_pid);
        }

        match search_stack.pop() {
            Some(search_pid) => {
                pid = search_pid;
                pids.push(search_pid);
            }
            None => break,
        }
    }

    pids
}

fn inode_exists(pid: u32, inode: u64) -> bool {
    let dir_path = Path::new("/proc").join(format!("{}", pid)).join("fd");

    let mut dir_list = dir_path.read_dir().unwrap();

    while let Some(Ok(file)) = dir_list.next() {
        let content_path = match file.path().read_link() {
            Ok(content_path) => content_path.to_str().unwrap().to_string(),
            Err(e) => {
                error!(
                    "failed to read link: {}, err: {}",
                    file.path().to_str().unwrap(),
                    e
                );
                return false;
            }
        };

        if content_path == format!("socket:[{}]", inode) {
            return true;
        }
    }

    false
}

fn get_process_name(pid: u32) -> String {
    let path = Path::new("/proc").join(format!("{}", pid)).join("comm");

    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(_) => return "".to_string(),
    };

    let mut name = String::new();

    file.read_to_string(&mut name).unwrap();

    name.trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEADER: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode";

    #[test]
    fn reads_the_port_and_inode() {
        let row = "   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000  00000000     0        0 24052 1 0000000000000000 100 0 0 10 0";
        assert_eq!(parse_net_row(row), Some((0x1F90, 24052)));
    }

    #[test]
    fn reads_an_ipv6_row() {
        let row = "   1: 00000000000000000000000000000000:0050 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000  00000000     0        0 31337 1 0000000000000000 100 0 0 10 0";
        assert_eq!(parse_net_row(row), Some((80, 31337)));
    }

    #[test]
    fn skips_the_header() {
        assert_eq!(parse_net_row(HEADER), None);
    }

    #[test]
    fn skips_short_or_malformed_rows() {
        // Used to panic on `row[1]` / `row[9]`.
        assert_eq!(parse_net_row(""), None);
        assert_eq!(parse_net_row("   0:"), None);
        assert_eq!(parse_net_row("   0: 0100007F:1F90"), None);
        assert_eq!(
            parse_net_row("   0: no-colon-here 0 0 0 0 0 0 0 0 24052"),
            None
        );
    }
}
