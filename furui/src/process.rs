use std::fs::{read_dir, read_link, File};
use std::io::{BufRead, BufReader, Read};
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::anyhow;
use tokio::sync::Mutex;
use tracing::error;

use furui_common::protocol_str_to_value;

use crate::domain::{Containers, Process};

static SUPPORTED_PROTOCOLS: [&str; 4] = ["tcp", "udp", "tcp6", "udp6"];

pub async fn get_all(containers: Arc<Mutex<Containers>>) -> Vec<Process> {
    let mut processes = vec![];

    for container in containers.lock().await.list() {
        for supported_protocol in &SUPPORTED_PROTOCOLS {
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
                let row = line.split_whitespace().collect::<Vec<&str>>();

                let port =
                    match u16::from_str_radix(row[1].split(":").collect::<Vec<&str>>()[1], 16) {
                        Ok(port) => port,
                        Err(_) => continue,
                    };

                let inode: u64 = match row[9].parse() {
                    Ok(port) => port,
                    Err(_) => continue,
                };

                let (executable, pid) = match search_process_from_inode(container.pid, inode) {
                    Some(value) => value,
                    None => continue,
                };

                processes.push(Process {
                    container_id: container.id.clone().unwrap(),
                    executable,
                    protocol: protocol_str_to_value(supported_protocol),
                    port,
                    pid,
                })
            }
        }
    }

    processes
}

fn search_process_from_inode(pid: i64, inode: u64) -> Option<(String, i64)> {
    let container_shim_pid = get_ppid(pid);

    let child_pids = get_child_pids(container_shim_pid);

    for child_pid in child_pids {
        if inode_exists(child_pid, inode) {
            return Some((get_process_name(child_pid), child_pid));
        }
    }

    None
}

fn get_ppid(pid: i64) -> i64 {
    let path = Path::new("/proc").join(format!("{}", pid)).join("stat");

    let file = match File::open(path) {
        Ok(file) => file,
        Err(_) => return 0,
    };

    let mut file_buf = BufReader::new(file).lines();
    i64::from_str(
        file_buf
            .next()
            .unwrap()
            .unwrap()
            .split_whitespace()
            .collect::<Vec<&str>>()[3],
    )
    .unwrap_or(0)
}

fn get_child_pids(pid: i64) -> Vec<i64> {
    let mut pid = pid;

    let mut search_stack: Vec<i64> = vec![];
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
                .map(|pid| pid.parse::<i64>().unwrap())
                .collect::<Vec<i64>>(),
            None => vec![],
        };

        for child_pid in child_pids {
            search_stack.push(child_pid);
        }

        match search_stack.pop() {
            Some(search_pid) => {
                println!("{:?}", search_stack);
                pid = search_pid;
                pids.push(search_pid);
            }
            None => break,
        }
    }

    pids
}

fn inode_exists(pid: i64, inode: u64) -> bool {
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

fn get_process_name(pid: i64) -> String {
    let path = Path::new("/proc").join(format!("{}", pid)).join("comm");

    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(_) => return "".to_string(),
    };

    let mut name = String::new();

    file.read_to_string(&mut name).unwrap();

    name.trim().to_string()
}
