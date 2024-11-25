use std::{collections::HashMap, convert::TryFrom, future::Future, sync::Arc};

use aya::{maps::perf::AsyncPerfEventArray, util::online_cpus, Ebpf};
use bind::*;
use bytes::BytesMut;
use close::*;
use connect::*;
use egress::*;
use furui_common::IpProtocol;
use ingress::*;
use tokio::{sync::Mutex, task};

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

    unsafe fn add(&mut self, pid: u32, container_id: String, port: u16, protocol: IpProtocol) {
        let mut key: Process = Default::default();

        key.container_id = container_id;
        key.port = port;
        key.protocol = protocol;

        match self.map.get_mut(&pid) {
            Some(processes) => {
                processes.push(key);
            }
            None => {
                self.map.insert(pid, vec![key]);
            }
        }
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

async fn handle_perf_array<E, A, F, Fut>(
    bpf: Arc<Mutex<Ebpf>>,
    map_name: &str,
    args: Arc<Mutex<A>>,
    callback: F,
) -> anyhow::Result<()>
where
    E: Send,
    A: Send + 'static,
    F: Fn(E, Arc<Mutex<A>>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send,
{
    let shared_callback = Arc::from(callback);

    let perf_array = Arc::new(Mutex::new(AsyncPerfEventArray::try_from(
        bpf.lock().await.take_map(map_name).unwrap(),
    )?));

    for cpu_id in online_cpus().unwrap() {
        let current_perf_array = perf_array.clone();
        let current_args = args.clone();
        let current_callback = shared_callback.clone();

        task::spawn(async move {
            let mut buf = current_perf_array.lock().await.open(cpu_id, None).unwrap();

            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();

            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();

                for i in 0..events.read {
                    let buf = &mut buffers[i];

                    let event = unsafe { (buf.as_ptr() as *const E).read_unaligned() };

                    current_callback(event, current_args.clone()).await;
                }
            }
        });
    }

    Ok(())
}
