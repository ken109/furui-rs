use log::info;
use simplelog::{ColorChoice, ConfigBuilder, LevelFilter, TermLogger, TerminalMode};
use structopt::StructOpt;
use tokio::signal;

mod load;

#[derive(Debug, StructOpt)]
struct Opt {
    #[structopt(short, long, default_value = "eth0")]
    iface: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::from_args();

    TermLogger::init(
        LevelFilter::Debug,
        ConfigBuilder::new()
            .set_target_level(LevelFilter::Error)
            .set_location_level(LevelFilter::Error)
            .build(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )?;

    load::bind()?;
    load::connect()?;
    load::close()?;
    load::ingress(&opt.iface)?;
    load::ingress_icmp(&opt.iface)?;
    load::egress(&opt.iface)?;
    load::egress_icmp(&opt.iface)?;

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
