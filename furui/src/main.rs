use std::path::PathBuf;
use std::sync::Arc;

use anyhow::anyhow;
use structopt::StructOpt;
use thiserror::Error;
use tokio::signal;
use tokio::sync::Mutex;
use tracing::{error, info};
use tracing_core::Level;
use tracing_log::LogTracer;
use tracing_subscriber::FmtSubscriber;

use crate::docker::Docker;
use crate::domain::Containers;
use crate::map::Maps;
use crate::parse_policy::ParsePolicies;

mod docker;
mod domain;
mod ebpf;
mod handle;
mod map;
mod parse_policy;
mod process;

#[derive(Debug, StructOpt, Clone)]
struct Opt {
    #[structopt(short, long, default_value = "eth0")]
    iface: String,

    policy_path: PathBuf,

    #[cfg_attr(debug_assertions, structopt(long, default_value = "debug", possible_values = &["trace", "debug", "info", "warn", "error"]))]
    #[cfg_attr(not(debug_assertions), structopt(long, default_value = "info", possible_values = &["trace", "debug", "info", "warn", "error"]))]
    log_level: String,

    #[structopt(long, default_value = "text", possible_values = &["json", "text"])]
    log_fmt: String,
}

#[tokio::main]
async fn main() {
    let opt: Opt = Opt::from_args();

    match unsafe { try_main(opt.clone()).await } {
        Ok(_) => (),
        Err(err) => {
            #[cfg(debug_assertions)]
            println!("{:?}", err);
            #[cfg(not(debug_assertions))]
            println!("{}", err);
        }
    };

    ebpf::detach_programs(&opt.iface);
}

async unsafe fn try_main(opt: Opt) -> anyhow::Result<()> {
    if libc::geteuid() != 0 {
        return Err(anyhow!("You must be root."));
    }

    setup_tracing(&opt)?;

    let docker = Docker::new()?;

    let containers = Containers::new();

    docker
        .add_running_containers_inspect(containers.clone())
        .await?;

    let policies = match ParsePolicies::new(opt.policy_path) {
        Ok(parsed_policies) => parsed_policies.to_domain(containers.clone()).await?,
        Err(err) => {
            return Err(err);
        }
    };

    let mut bpf = ebpf::load_bpf()?;
    ebpf::attach_programs(&mut bpf, &opt.iface)?;

    let bpf = Arc::new(Mutex::new(bpf));
    let maps = Maps::new(bpf.clone());

    let processes = process::get_all(containers.clone()).await;

    policies
        .lock()
        .await
        .set_container_id(containers.clone())
        .await;

    maps.policy.save(policies.clone()).await?;
    maps.container.save_id_with_ips(containers.clone()).await?;
    maps.process.save_all(&processes).await?;

    handle::all_perf_events(bpf.clone(), maps.clone(), &processes).await?;
    handle::docker_events(docker.clone(), maps.clone(), containers.clone(), policies);

    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}

#[derive(Error, Debug)]
enum SetupTracingError {
    #[error(transparent)]
    SetLogger(#[from] log::SetLoggerError),

    #[error(transparent)]
    SetGlobalDefault(#[from] tracing_core::dispatcher::SetGlobalDefaultError),

    #[error("unknown log level")]
    UnknownLogLevel,

    #[error("unknown log message format")]
    UnknownLogFormat,
}

fn setup_tracing(opt: &Opt) -> Result<(), SetupTracingError> {
    let (level_tracing, level_log) = match opt.log_level.as_str() {
        "trace" => (Level::TRACE, log::LevelFilter::Trace),
        "debug" => (Level::DEBUG, log::LevelFilter::Debug),
        "info" => (Level::INFO, log::LevelFilter::Info),
        "warn" => (Level::WARN, log::LevelFilter::Warn),
        "error" => (Level::ERROR, log::LevelFilter::Error),
        _ => return Err(SetupTracingError::UnknownLogLevel),
    };

    let builder = FmtSubscriber::builder().with_max_level(level_tracing);
    match opt.log_fmt.as_str() {
        "json" => {
            let subscriber = builder.json().finish();
            tracing::subscriber::set_global_default(subscriber)?;
        }
        "text" => {
            let subscriber = builder.finish();
            tracing::subscriber::set_global_default(subscriber)?;
        }
        _ => return Err(SetupTracingError::UnknownLogFormat),
    };

    LogTracer::builder().with_max_level(level_log).init()?;

    Ok(())
}
