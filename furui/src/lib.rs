//! Container communication control, enforced with eBPF.
//!
//! The crate is layered as:
//!
//! * [`cli`] and [`telemetry`] -- process setup.
//! * [`domain`] -- the policy and container model everything else speaks in.
//! * [`policy`] -- reading policy files and following changes to them.
//! * [`runtime`] -- docker/CRI: which containers exist and what happens to them.
//! * [`procfs`] -- which processes inside those containers hold which sockets.
//! * [`bpf`] -- loading the programs, seeding their maps, draining their events.
//! * [`app`] -- wiring those together.

pub use app::{cleanup, start};
pub use cli::{ContainerRuntime, LogFormat, LogLevel, Options};

mod app;
mod bpf;
mod cli;
mod domain;
mod policy;
mod procfs;
mod runtime;
mod telemetry;
