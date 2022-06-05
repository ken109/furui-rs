use std::path::PathBuf;
use std::process;

use aya::{Bpf, include_bytes_aligned};
use log::info;
use simplelog::{ColorChoice, ConfigBuilder, LevelFilter, TerminalMode, TermLogger};
use structopt::StructOpt;
use tokio::signal;

use crate::parse_policy::ParsePolicies;

mod load;
mod handle;
mod parse_policy;
mod domain;

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
        println!("You must be root.");
        process::exit(1);
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

    let policies = match ParsePolicies::new(opt.policy_path) {
        Ok(parsed_policies) => parsed_policies.to_domain()?,
        Err(err) => {
            println!("{}", err);
            process::exit(1);
        }
    };

    println!("{:#?}", policies);

    process::exit(0);

    #[cfg(debug_assertions)]
        let mut bpf = Bpf::load(include_bytes_aligned!("../../target/bpfel-unknown-none/debug/bind"))?;
    #[cfg(not(debug_assertions))]
        let mut bpf = Bpf::load(include_bytes_aligned!("../../target/bpfel-unknown-none/release/bind"))?;
    load::bind(&mut bpf)?;

    #[cfg(debug_assertions)]
        let mut bpf = Bpf::load(include_bytes_aligned!("../../target/bpfel-unknown-none/debug/connect"))?;
    #[cfg(not(debug_assertions))]
        let mut bpf = Bpf::load(include_bytes_aligned!("../../target/bpfel-unknown-none/release/connect"))?;
    load::connect(&mut bpf)?;

    #[cfg(debug_assertions)]
        let mut bpf = Bpf::load(include_bytes_aligned!("../../target/bpfel-unknown-none/debug/close"))?;
    #[cfg(not(debug_assertions))]
        let mut bpf = Bpf::load(include_bytes_aligned!("../../target/bpfel-unknown-none/release/close"))?;
    load::close(&mut bpf)?;

    #[cfg(debug_assertions)]
        let mut bpf = Bpf::load(include_bytes_aligned!("../../target/bpfel-unknown-none/debug/ingress"))?;
    #[cfg(not(debug_assertions))]
        let mut bpf = Bpf::load(include_bytes_aligned!("../../target/bpfel-unknown-none/release/ingress"))?;
    load::ingress(&mut bpf, &opt.iface)?;

    #[cfg(debug_assertions)]
        let mut bpf = Bpf::load(include_bytes_aligned!("../../target/bpfel-unknown-none/debug/ingress_icmp"))?;
    #[cfg(not(debug_assertions))]
        let mut bpf = Bpf::load(include_bytes_aligned!("../../target/bpfel-unknown-none/release/ingress_icmp"))?;
    load::ingress_icmp(&mut bpf, &opt.iface)?;

    #[cfg(debug_assertions)]
        let mut bpf = Bpf::load(include_bytes_aligned!("../../target/bpfel-unknown-none/debug/egress"))?;
    #[cfg(not(debug_assertions))]
        let mut bpf = Bpf::load(include_bytes_aligned!("../../target/bpfel-unknown-none/release/egress"))?;
    load::egress(&mut bpf, &opt.iface)?;

    #[cfg(debug_assertions)]
        let mut bpf = Bpf::load(include_bytes_aligned!("../../target/bpfel-unknown-none/debug/egress_icmp"))?;
    #[cfg(not(debug_assertions))]
        let mut bpf = Bpf::load(include_bytes_aligned!("../../target/bpfel-unknown-none/release/egress_icmp"))?;
    load::egress_icmp(&mut bpf, &opt.iface)?;

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
