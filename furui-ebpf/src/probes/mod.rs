//! kprobes and tracepoints that track socket ownership.
//!
//! These record which process inside which container holds a given port, so
//! that the tc classifiers can attribute a packet to an executable name.

mod bind;
mod close;
mod connect;
