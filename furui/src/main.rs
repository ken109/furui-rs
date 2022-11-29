use clap::Parser;
use tokio::select;
use tokio::signal::unix::{signal, SignalKind};
use tracing::info;

use furui;
use furui::Options;

#[tokio::main]
async fn main() {
    let opt: Options = Options::parse();

    match unsafe { try_main(opt.clone()).await } {
        Ok(_) => (),
        Err(err) => {
            #[cfg(debug_assertions)]
            println!("{:?}", err);
            #[cfg(not(debug_assertions))]
            println!("{}", err);
        }
    };

    furui::cleanup();
}

async unsafe fn try_main(opt: Options) -> anyhow::Result<()> {
    furui::start(opt).await?;

    let mut sig_int = signal(SignalKind::interrupt()).unwrap();
    let mut sig_term = signal(SignalKind::terminate()).unwrap();
    select! {
        _ = sig_int.recv() => {},
        _ = sig_term.recv() => {},
    }
    info!("Exiting...");

    Ok(())
}
