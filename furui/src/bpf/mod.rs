//! Everything that touches the loaded eBPF object.
//!
//! [`loader`] loads and attaches the programs, [`maps`] seeds the maps the
//! programs look policies up in, and [`events`] drains the perf buffers they
//! report through.

pub use events::watch_perf_events;
pub use loader::{detach_programs, load, Loader};
pub use maps::Maps;

mod events;
mod loader;
mod maps;
