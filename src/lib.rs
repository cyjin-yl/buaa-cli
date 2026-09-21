//! Agent-facing BUAA utilities and mandatory shared request-safety primitives.
//! Campus gateway code is explicit opt-in and live-unverified; archive access is also opt-in.
pub mod archive;
pub mod gateway;
pub mod governor;
pub mod net;
pub mod timed_input;
