extern crate core;

use std::path::PathBuf;

use anyhow::anyhow;
use aya::{include_bytes_aligned, Bpf};
use structopt::StructOpt;
use thiserror::Error;
use tokio::signal;
use tracing::info;
use tracing_core::Level;
use tracing_log::LogTracer;
use tracing_subscriber::FmtSubscriber;

use crate::docker::Docker;
use crate::domain::Containers;
use crate::map::{ContainerMap, Maps};
use crate::parse_policy::ParsePolicies;

mod docker;
mod domain;
mod handle;
mod load;
mod map;
mod parse_policy;

#[derive(Debug, StructOpt)]
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
    match try_main().await {
        Ok(_) => (),
        Err(err) => {
            println!("{}", err)
        }
    }
}

async fn try_main() -> anyhow::Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(anyhow!("You must be root."));
    }

    let opt = Opt::from_args();

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

    let mut bpf = load::all_programs(&opt.iface)?;
    let maps = Maps::new(&mut bpf);

    maps.container.save_id_with_ips(containers.clone()).await?;

    handle::all_perf_events(&mut bpf)?;
    handle::docker_events(docker.clone(), containers.clone());

    info!("Waiting for Ctrl-C...");
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
