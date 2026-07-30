//! Policy files: reading them, converting them, and following changes.

pub use watcher::watch_file;
pub use yaml::ParsePolicies;

mod loader;
mod watcher;
mod yaml;
