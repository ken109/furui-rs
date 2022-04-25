use std::convert::TryFrom;
use std::sync::Arc;

use aya::Bpf;
use aya::maps::perf::AsyncPerfEventArray;
use aya::util::online_cpus;
use bytes::BytesMut;
use tokio::task;

pub use bind::*;
pub use connect::*;

mod bind;
mod connect;

type Callback<E> = dyn Fn(E) + Send + Sync + 'static;

fn handle_perf_array<E: 'static>(bpf: &mut Bpf, map_name: &str, callback: Box<Callback<E>>) -> Result<(), anyhow::Error> {
    let shared_callback: Arc<Callback<E>> = Arc::from(callback);

    let mut perf_array = AsyncPerfEventArray::try_from(bpf.map_mut(map_name)?)?;

    for cpu_id in online_cpus()? {
        let mut buf = perf_array.open(cpu_id, None)?;

        let current_callback = shared_callback.clone();

        task::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();

            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();

                for i in 0..events.read {
                    let buf = &mut buffers[i];
                    let ptr = buf.as_ptr() as *const E;

                    let event = unsafe { ptr.read_unaligned() };

                    current_callback(event);
                }
            }
        });
    }

    Ok(())
}
