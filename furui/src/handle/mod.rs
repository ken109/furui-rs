use std::collections::HashMap;
use std::convert::TryFrom;
use std::future::Future;
use std::mem::MaybeUninit;
use std::sync::Arc;

use aya::maps::perf::AsyncPerfEventArray;
use aya::util::online_cpus;
use aya::Bpf;
use aya_bpf::cty::c_char;
use bytes::BytesMut;
use tokio::sync::Mutex;
use tokio::task;

use bind::*;
use close::*;
use connect::*;
pub use docker::docker_events;

use crate::domain::Process;
use crate::Maps;

mod bind;
mod close;
mod connect;
mod docker;

pub struct PidProcesses {
    map: HashMap<u32, Vec<Process>>,
}

impl PidProcesses {
    fn new() -> PidProcesses {
        PidProcesses {
            map: HashMap::<u32, Vec<Process>>::new(),
        }
    }

    unsafe fn add(&mut self, pid: u32, container_id: String, port: u16, protocol: u8) {
        let mut key_uninit = MaybeUninit::<Process>::zeroed();
        let mut key_ptr = key_uninit.as_mut_ptr();
        (*key_ptr).container_id = container_id;
        (*key_ptr).port = port;
        (*key_ptr).protocol = protocol;

        match self.map.get_mut(&pid) {
            Some(processes) => {
                processes.push(key_uninit.assume_init());
            }
            None => {
                self.map.insert(pid, vec![key_uninit.assume_init()]);
            }
        }
    }
}

pub async unsafe fn all_perf_events(
    bpf: Arc<Mutex<Bpf>>,
    maps: Arc<Mutex<Maps>>,
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
    connect6(bpf.clone(), pid_processes.clone()).await?;
    close(bpf.clone(), maps, pid_processes.clone()).await?;

    Ok(())
}

async fn handle_perf_array<A, E, F, Fut>(
    bpf: Arc<Mutex<Bpf>>,
    map_name: &str,
    args: Arc<Mutex<A>>,
    callback: F,
) -> anyhow::Result<()>
where
    A: Send + 'static,
    E: Send + 'static,
    F: Fn(E, Arc<Mutex<A>>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let shared_callback = Arc::from(callback);

    let mut perf_array = AsyncPerfEventArray::try_from(bpf.lock().await.map_mut(map_name)?)?;

    for cpu_id in online_cpus()? {
        let mut buf = perf_array.open(cpu_id, None)?;

        let current_args = args.clone();
        let current_callback = shared_callback.clone();

        task::spawn(async move {
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

fn to_str<const N: usize>(array: [c_char; N]) -> String {
    array
        .iter()
        .map(|&s| (s as u8) as char)
        .collect::<String>()
        .split("\0")
        .nth(0)
        .unwrap_or("")
        .to_string()
}
