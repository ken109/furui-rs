use aya_bpf::cty::{c_char, c_long};
use aya_bpf::helpers::{bpf_get_current_task, bpf_probe_read_kernel};

use furui_common::CONTAINER_ID_LEN;
pub(crate) use net::*;

use crate::vmlinux::task_struct;

mod net;

#[inline]
pub(crate) unsafe fn is_container_process() -> Result<bool, c_long> {
    let task = &*(bpf_get_current_task() as *const task_struct);

    let nsproxy = &*bpf_probe_read_kernel(&task.nsproxy)?;
    let pidns = &*bpf_probe_read_kernel(&nsproxy.pid_ns_for_children)?;

    return Ok(bpf_probe_read_kernel(&pidns.level)? > 0);
}

#[inline]
pub(crate) unsafe fn get_container_id() -> Result<[c_char; CONTAINER_ID_LEN], c_long> {
    let task = &*(bpf_get_current_task() as *const task_struct);

    let nsproxy = &*bpf_probe_read_kernel(&task.nsproxy)?;
    let uts = &*bpf_probe_read_kernel(&nsproxy.uts_ns)?;

    return Ok(*bpf_probe_read_kernel(&uts.name.nodename)?
        .as_ptr()
        .cast::<[c_char; CONTAINER_ID_LEN]>());
}
