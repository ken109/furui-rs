//! Logging setup.

use thiserror::Error;
use tracing_core::Level;
use tracing_log::LogTracer;
use tracing_subscriber::FmtSubscriber;

use crate::cli::{LogFormat, LogLevel, Options};

#[derive(Error, Debug)]
pub enum SetupTracingError {
    #[error(transparent)]
    SetLogger(#[from] log::SetLoggerError),

    #[error(transparent)]
    SetGlobalDefault(#[from] tracing_core::dispatcher::SetGlobalDefaultError),
}

/// Installs the global subscriber and bridges the `log` crate into it.
///
/// The bridge matters: aya logs through `log`, so without it the eBPF loader's
/// diagnostics go nowhere.
pub fn setup(opt: &Options) -> Result<(), SetupTracingError> {
    let (level_tracing, level_log) = match opt.log_level {
        LogLevel::Trace => (Level::TRACE, log::LevelFilter::Trace),
        LogLevel::Debug => (Level::DEBUG, log::LevelFilter::Debug),
        LogLevel::Info => (Level::INFO, log::LevelFilter::Info),
        LogLevel::Warn => (Level::WARN, log::LevelFilter::Warn),
        LogLevel::Error => (Level::ERROR, log::LevelFilter::Error),
    };

    let builder = FmtSubscriber::builder().with_max_level(level_tracing);
    match opt.log_fmt {
        LogFormat::Json => {
            let subscriber = builder.json().finish();
            tracing::subscriber::set_global_default(subscriber)?;
        }
        LogFormat::Text => {
            let subscriber = builder.finish();
            tracing::subscriber::set_global_default(subscriber)?;
        }
    };

    LogTracer::builder().with_max_level(level_log).init()?;

    Ok(())
}
