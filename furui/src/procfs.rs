use std::{
    fs::File,
    io::{BufRead, BufReader, Read},
    path::Path,
    str::FromStr,
    sync::Arc,
};

use furui_common::IpProtocol;
use tokio::sync::RwLock;
use tracing::debug;

use crate::domain::{Containers, Process};

static SUPPORTED_PROTOCOLS: [(&str, IpProtocol); 4] = [
    ("tcp", IpProtocol::TCP),
    ("udp", IpProtocol::UDP),
    ("tcp6", IpProtocol::TCP),
    ("udp6", IpProtocol::UDP),
];

pub async fn listening_processes(containers: Arc<RwLock<Containers>>) -> Vec<Process> {
    let mut processes = vec![];

    for container in containers.read().await.list() {
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
                    container_id: container.id.clone(),
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

/// The parent pid from `/proc/<pid>/stat`, or 0 if it cannot be read.
///
/// Everything under `/proc` can vanish between the readdir and the read, so
/// none of these helpers treat a missing or malformed file as exceptional --
/// the process simply exited.
fn get_ppid(pid: u32) -> u32 {
    let path = Path::new("/proc").join(pid.to_string()).join("stat");

    let Ok(file) = File::open(path) else {
        return 0;
    };
    let Some(Ok(line)) = BufReader::new(file).lines().next() else {
        return 0;
    };

    parse_ppid(&line).unwrap_or(0)
}

/// Extracts the `ppid` field from a `/proc/<pid>/stat` line.
///
/// The second field is the executable name in parentheses and may itself
/// contain spaces and parentheses, so the fields before it cannot be split on
/// whitespace. Everything after the *last* `)` is fixed-width: state, then
/// ppid.
fn parse_ppid(stat: &str) -> Option<u32> {
    let after_comm = &stat[stat.rfind(')')? + 1..];
    let mut fields = after_comm.split_whitespace();

    fields.next()?; // state
    u32::from_str(fields.next()?).ok()
}

/// Every descendant of `pid`, depth-first.
fn get_child_pids(pid: u32) -> Vec<u32> {
    let mut stack = vec![pid];
    let mut descendants = vec![];

    while let Some(pid) = stack.pop() {
        for child in read_children(pid) {
            descendants.push(child);
            stack.push(child);
        }
    }

    descendants
}

/// The direct children of `pid`.
///
/// An unreadable `children` file means the process is gone, which is the same
/// as having no children -- it must not abandon the descendants already found.
fn read_children(pid: u32) -> Vec<u32> {
    let path = Path::new("/proc")
        .join(pid.to_string())
        .join("task")
        .join(pid.to_string())
        .join("children");

    let Ok(file) = File::open(path) else {
        return vec![];
    };
    let Some(Ok(line)) = BufReader::new(file).lines().next() else {
        return vec![];
    };

    line.split_whitespace()
        .filter_map(|pid| pid.parse().ok())
        .collect()
}

/// Whether `pid` holds a socket with this inode.
fn inode_exists(pid: u32, inode: u64) -> bool {
    let dir_path = Path::new("/proc").join(pid.to_string()).join("fd");

    let Ok(dir_list) = dir_path.read_dir() else {
        return false;
    };
    let socket = format!("socket:[{inode}]");

    for file in dir_list.flatten() {
        match file.path().read_link() {
            // A descriptor closing mid-scan is routine; keep looking rather
            // than reporting the whole process as not holding the socket.
            Ok(target) => {
                if target.to_string_lossy() == socket {
                    return true;
                }
            }
            Err(err) => debug!("failed to read link {}: {err}", file.path().display()),
        }
    }

    false
}

fn get_process_name(pid: u32) -> String {
    let path = Path::new("/proc").join(pid.to_string()).join("comm");

    let Ok(mut file) = File::open(path) else {
        return String::new();
    };

    let mut name = String::new();
    if file.read_to_string(&mut name).is_err() {
        return String::new();
    }

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
    fn reads_the_ppid_past_a_name_containing_spaces() {
        // The comm field is parenthesised and may contain spaces and
        // parentheses; splitting the whole line on whitespace used to pick the
        // wrong field for anything but a single-word name.
        assert_eq!(parse_ppid("42 (nginx) S 7 42 42 0 -1 4194304").unwrap(), 7);
        assert_eq!(parse_ppid("42 (my app) S 7 42 42 0 -1 4194304").unwrap(), 7);
        assert_eq!(parse_ppid("42 (a (b) c) S 7 42 42 0 -1").unwrap(), 7);
    }

    #[test]
    fn a_malformed_stat_line_has_no_ppid() {
        assert_eq!(parse_ppid(""), None);
        assert_eq!(parse_ppid("42 (nginx)"), None);
        assert_eq!(parse_ppid("42 (nginx) S"), None);
        assert_eq!(parse_ppid("42 (nginx) S notanumber"), None);
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
