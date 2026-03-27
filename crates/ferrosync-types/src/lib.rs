//! # ferrosync-types
//!
//! Core types, traits, configuration, and error definitions for ferrosync.
//!
//! This is the foundation crate that all other ferrosync crates depend on.
//! It contains the "what" layer: type definitions, configuration structs,
//! error enums, and semantic newtypes -- with zero implementation logic.

pub mod constants;
pub mod error;
pub mod mode;
pub mod options;
pub mod protocol;
pub mod stats;
pub mod types;

pub use error::FerrosyncError;
