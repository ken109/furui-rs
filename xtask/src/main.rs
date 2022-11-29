use std::process::exit;

use clap::Parser;

mod aya_gen;
mod build_ebpf;
mod run;

#[derive(Debug, Parser)]
pub struct Options {
    #[structopt(subcommand)]
    command: Command,
}

#[derive(Debug, Parser)]
enum Command {
    BuildEbpf(build_ebpf::Options),
    Run(run::Options),
    AyaGen,
}

fn main() {
    let opts = Options::from_args();

    use Command::*;
    let ret = match opts.command {
        BuildEbpf(opts) => build_ebpf::build_ebpf(opts),
        Run(opts) => run::run(opts),
        AyaGen => aya_gen::aya_gen(),
    };

    if let Err(e) = ret {
        eprintln!("{:#}", e);
        exit(1);
    }
}
