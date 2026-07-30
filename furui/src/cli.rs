//! Command-line surface.

use std::path::PathBuf;

use clap::Parser;

#[derive(clap::ValueEnum, PartialEq, Eq, Debug, Clone)]
pub enum ContainerRuntime {
    Docker,
    KubernetesCri,
}

#[derive(clap::ValueEnum, PartialEq, Eq, Debug, Clone)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

#[derive(clap::ValueEnum, PartialEq, Eq, Debug, Clone)]
pub enum LogFormat {
    Json,
    Text,
}

#[derive(Debug, Clone, Parser)]
pub struct Options {
    #[arg(long, short = 'e', value_enum, default_value = "docker")]
    pub container_engine: ContainerRuntime,

    /// Path to the policy file to enforce.
    pub policy_path: PathBuf,

    #[cfg_attr(debug_assertions, arg(long, value_enum, default_value = "debug"))]
    #[cfg_attr(not(debug_assertions), arg(long, value_enum, default_value = "info"))]
    pub log_level: LogLevel,

    #[arg(long, value_enum, default_value = "text")]
    pub log_fmt: LogFormat,
}
