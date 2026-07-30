//! Wiring the pieces together.

use anyhow::anyhow;

use crate::{
    bpf::{self, Loader, Maps},
    cli::Options,
    domain::Containers,
    policy::{self, ParsePolicies},
    procfs,
    runtime::{self, Runtime},
    telemetry,
};

/// Loads the eBPF programs, seeds the maps and spawns the event loops.
///
/// Returns once everything is attached; the spawned tasks keep running until
/// the process exits.
///
/// # Safety
///
/// Events are read out of perf buffers by reinterpreting the raw bytes the
/// kernel side wrote. The caller must ensure the loaded eBPF object is the one
/// built from `furui-ebpf` in this workspace, so that the event structs on both
/// sides agree.
pub async unsafe fn start(opt: Options) -> anyhow::Result<()> {
    // SAFETY: `geteuid` is always safe to call.
    if unsafe { libc::geteuid() } != 0 {
        return Err(anyhow!("You must be root."));
    }

    telemetry::setup(&opt)?;

    let container_engine = Runtime::new(&opt).await?;
    let containers = Containers::new();

    container_engine
        .add_running_containers_inspect(containers.clone())
        .await?;

    let policies = ParsePolicies::new(opt.policy_path.clone())?
        .to_policies(containers.clone())
        .await?;

    let bpf = bpf::load()?;
    let loader = Loader::new(bpf.clone());

    loader.attach_programs().await?;

    let processes = procfs::listening_processes(containers.clone()).await;

    let maps = Maps::new(bpf.clone());
    maps.policy.save(policies.clone()).await?;
    maps.container.save_id_with_ips(containers.clone()).await?;
    // SAFETY: same contract as this function's.
    unsafe { maps.process.save_all(&processes) }.await?;

    // SAFETY: same contract as this function's.
    unsafe { bpf::watch_perf_events(bpf.clone(), maps.clone(), &processes) }.await?;
    runtime::watch_containers(
        loader.clone(),
        container_engine.clone(),
        maps.clone(),
        containers.clone(),
        policies.clone(),
    );
    policy::watch_file(
        opt.policy_path.clone(),
        maps.clone(),
        policies.clone(),
        containers.clone(),
    )?;

    Ok(())
}

/// Detaches the tc classifiers this process attached.
///
/// The kprobes and tracepoints go away with the process; the clsact qdiscs do
/// not, so they have to be torn down explicitly.
pub fn cleanup() {
    bpf::detach_programs();
}
