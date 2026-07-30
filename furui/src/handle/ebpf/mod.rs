use std::{collections::HashMap, convert::TryFrom, future::Future, mem, sync::Arc};

use anyhow::anyhow;
use aya::{
    maps::{perf::PerfEvent, MapData, PerfEventArray},
    util::online_cpus,
    Ebpf,
};
use bind::*;
use close::*;
use connect::*;
use egress::*;
use furui_common::IpProtocol;
use ingress::*;
use tokio::{io::unix::AsyncFd, sync::Mutex, task};
use tracing::warn;

use crate::{domain::Process, Maps};

mod bind;
mod close;
mod connect;

mod egress;
mod ingress;

pub struct PidProcesses {
    map: HashMap<u32, Vec<Process>>,
}

impl PidProcesses {
    fn new() -> PidProcesses {
        PidProcesses {
            map: HashMap::<u32, Vec<Process>>::new(),
        }
    }

    fn add(&mut self, pid: u32, container_id: String, port: u16, protocol: IpProtocol) {
        let key = Process {
            container_id,
            port,
            protocol,
            ..Default::default()
        };

        self.map.entry(pid).or_default().push(key);
    }
}

pub async unsafe fn perf_events(
    bpf: Arc<Mutex<Ebpf>>,
    maps: Arc<Maps>,
    processes: &Vec<Process>,
) -> anyhow::Result<()> {
    let pid_processes = Arc::new(Mutex::new(PidProcesses::new()));

    for process in processes {
        pid_processes.lock().await.add(
            process.pid,
            process.container_id.clone(),
            process.port,
            process.protocol,
        );
    }

    bind(bpf.clone(), pid_processes.clone()).await?;
    connect(bpf.clone(), pid_processes.clone()).await?;
    close(bpf.clone(), maps, pid_processes.clone()).await?;

    ingress(bpf.clone()).await?;
    egress(bpf.clone()).await?;

    Ok(())
}

/// Reassembles an event of type `E` from a perf sample.
///
/// The kernel ring buffer can split a sample across its wrap point, in which
/// case the payload arrives as `head` followed by `tail`.
///
/// # Safety
///
/// The sample bytes must be a valid instance of `E`. That holds as long as the
/// eBPF side writes the same `#[repr(C)]` type into this perf array.
unsafe fn decode_event<E>(head: &[u8], tail: &[u8]) -> Option<E> {
    let size = mem::size_of::<E>();
    if head.len() + tail.len() < size {
        return None;
    }

    if head.len() >= size {
        Some(head.as_ptr().cast::<E>().read_unaligned())
    } else {
        let mut bytes = vec![0u8; size];
        let split = head.len();
        bytes[..split].copy_from_slice(head);
        bytes[split..].copy_from_slice(&tail[..size - split]);
        Some(bytes.as_ptr().cast::<E>().read_unaligned())
    }
}

/// Drains `map_name` on every online CPU, invoking `callback` per event.
///
/// One task per CPU owns its own perf buffer, so a slow consumer on one CPU
/// cannot stall the others. Events are decoded while the readiness guard is
/// held and dispatched after it is released, since `for_each` is synchronous.
async fn handle_perf_array<E, A, F, Fut>(
    bpf: Arc<Mutex<Ebpf>>,
    map_name: &str,
    args: Arc<Mutex<A>>,
    callback: F,
) -> anyhow::Result<()>
where
    E: Send + 'static,
    A: Send + 'static,
    F: Fn(E, Arc<Mutex<A>>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send,
{
    let shared_callback = Arc::new(callback);

    let map = bpf
        .lock()
        .await
        .take_map(map_name)
        .ok_or_else(|| anyhow!("no such map: {map_name}"))?;
    let mut perf_array = PerfEventArray::<MapData>::try_from(map)?;

    let cpus = online_cpus().map_err(|(path, err)| anyhow!("failed to read {path}: {err}"))?;

    for cpu_id in cpus {
        let buf = perf_array.open(cpu_id, None)?;
        let current_args = args.clone();
        let current_callback = shared_callback.clone();
        let map_name = map_name.to_string();

        task::spawn(async move {
            let mut async_fd = match AsyncFd::new(buf) {
                Ok(async_fd) => async_fd,
                Err(err) => {
                    warn!("failed to watch {map_name} on cpu {cpu_id}: {err}");
                    return;
                }
            };

            let mut events: Vec<E> = Vec::new();
            loop {
                let mut guard = match async_fd.readable_mut().await {
                    Ok(guard) => guard,
                    Err(err) => {
                        warn!("failed to poll {map_name} on cpu {cpu_id}: {err}");
                        return;
                    }
                };

                guard.get_inner_mut().for_each(|event| match event {
                    PerfEvent::Sample { head, tail } => {
                        if let Some(event) = unsafe { decode_event::<E>(head, tail) } {
                            events.push(event);
                        }
                    }
                    PerfEvent::Lost { count } => {
                        warn!("{map_name} lost {count} events on cpu {cpu_id}");
                    }
                });
                guard.clear_ready();

                for event in events.drain(..) {
                    current_callback(event, current_args.clone()).await;
                }
            }
        });
    }

    Ok(())
}
