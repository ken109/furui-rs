extern crate core;

use std::path::PathBuf;

use anyhow::anyhow;
use aya::{include_bytes_aligned, Bpf};
use log::info;
use simplelog::{ColorChoice, ConfigBuilder, LevelFilter, TermLogger, TerminalMode};
use structopt::StructOpt;
use tokio::{signal, task};

use crate::docker::Docker;
use crate::domain::Containers;
use crate::parse_policy::ParsePolicies;

mod constant;
mod docker;
mod domain;
mod handle;
mod load;
mod parse_policy;

#[derive(Debug, StructOpt)]
struct Opt {
    #[structopt(short, long, default_value = "eth0")]
    iface: String,

    policy_path: PathBuf,
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

    #[cfg(debug_assertions)]
    let log_level = LevelFilter::Debug;
    #[cfg(not(debug_assertions))]
    let log_level = LevelFilter::Info;
    TermLogger::init(
        log_level,
        ConfigBuilder::new()
            .set_target_level(LevelFilter::Error)
            .set_location_level(LevelFilter::Error)
            .build(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )?;

    let docker = Docker::new()?;

    let mut containers = Containers::new();

    docker
        .add_running_containers_inspect(&mut containers)
        .await?;

    let policies = match ParsePolicies::new(opt.policy_path) {
        Ok(parsed_policies) => parsed_policies.to_domain(containers)?,
        Err(err) => {
            return Err(err);
        }
    };

    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/furui"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/furui"
    ))?;
    load::all_programs(&mut bpf, &opt.iface)?;

    task::spawn(async move { handle::docker(&docker).await });

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
