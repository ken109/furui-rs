use aya::Bpf;
use chrono::Local;
use log::info;

use furui_common::BindEvent;

use crate::handle::handle_perf_array;

pub fn bind(bpf: &mut Bpf) -> Result<(), anyhow::Error> {
    handle_perf_array(bpf, "BIND_EVENTS", Box::new(|event: BindEvent| {
        let time = Local::now().format("%H:%M:%S").to_string();

        info!("{} PID {} {:?}", time, event.pid, event.comm);
    }))?;

    Ok(())
}
